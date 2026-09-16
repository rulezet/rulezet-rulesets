rule Win_Trojan_Small_3485
{
strings:
	$a0 = { 888c889387574ec2ec7ee78467ee1024fa5dbe3594f77cbce040e3ee7a2cd784ca34d2219e1c49d57da3d07e4ca69907cc1d964ebca3ab5c6768c9d0b51807fe6ab1e9f1e64a76046ef4f037ee41 }


condition:
	$a0
}