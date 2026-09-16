rule Win_Spyware_W32_41
{
strings:
	$a0 = { 48a7c51f7565469eb848a9146286174d69348e257bddac0057fb7c0bdaf177d41d92ffcb6cfeddfdf31cbf86efa4b7b96ec6042be052b4fccc946cb1f842d3ea }


condition:
	$a0
}