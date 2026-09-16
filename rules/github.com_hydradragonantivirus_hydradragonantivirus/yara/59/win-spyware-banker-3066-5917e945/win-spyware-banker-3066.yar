rule Win_Spyware_Banker_3066
{
strings:
	$a0 = { e820e57a90ad2ebb90f928ae535005ebed5191864ab0ac93ca98d644b8a9d797ce75dd94a4d727ba61c26a6def1baef258b0f815b3f3a8ec7f00ceddc6fd }


condition:
	$a0
}