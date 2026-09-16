rule Win_Adware_Webhancer_12
{
strings:
	$a0 = { 6674776172655c77656248616e636572000011f35030b598cf11bb8200aa }


condition:
	$a0
}