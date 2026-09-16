rule Win_Spyware_Banker_2702
{
strings:
	$a0 = { 1af6ddf25acb990a9c6f3f802ed9b0f839f54f47e3a43a22e199cc64a761ead2c6ffd17794bbcefe56a9d603410d7e56ad6bc22b8eabf0b2285fce2acd9522ab5225188d1af0358144cc3b364771 }


condition:
	$a0
}