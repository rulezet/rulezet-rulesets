rule Win_Trojan_INT13_1
{
strings:
	$a0 = { bf4c005733ed8eddc41dbf7402895dfc8c45feb413cd2f0653cd2f8ec5be840058ab58ab56a5a5b452cd21061fc4471226ff7602be00018bce8bfd56f3 }


condition:
	$a0
}