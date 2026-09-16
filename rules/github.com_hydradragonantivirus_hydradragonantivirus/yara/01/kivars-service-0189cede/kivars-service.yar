rule kivars_service	
{
  meta:
    description	=	"Detects instances of	Kivars malware when	installed as a service"
    author = "cwilson@arbor.net"
    reference = "https://www.arbornetworks.com/blog/asert/wp-content/uploads/2016/04/ASERT-Threat-Intelligence-Report-2016-03-The-Four-Element-Sword-Engagement.pdf"
  strings:
    $s1	=	"\\Projects\\Br2012\\Release\\svc.pdb"
    $s2	=	"This	is a flag"
    $s3	=	"svc.dll"
    $s4	=	"ServiceMain"
    $s5	=	"winsta0"
  condition:
    uint16(0) == 0x5A4D and filesize	<	1000000 and	(all of	($s*))
}