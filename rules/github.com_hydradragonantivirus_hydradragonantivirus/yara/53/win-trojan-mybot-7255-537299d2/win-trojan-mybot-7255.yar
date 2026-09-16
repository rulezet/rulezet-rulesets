rule Win_Trojan_Mybot_7255
{
strings:
	$a0 = { 1134f36b8dbb54bf3d448b07cd653d6d492e65de9a5c348dd0330c2e3b2f38bf5449483ce4173e83eaa913c666afe74c1add04ef6a57047fb4185ea1bbe7cdf4e68c5c9f2600ed6631fa3e839e4b }


condition:
	$a0
}