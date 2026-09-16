import "pe"
rule _DrWeb_VirusFinding_Engine__InSoft_EDVSysteme_
{
	meta:
		description = "Dr.Web Virus-Finding Engine -> InSoft EDV-Systeme"
	strings:
		$0 = {B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04}
	condition:
		$0 at pe.entry_point
}