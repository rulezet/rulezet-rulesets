rule Win_Trojan_Agent_35108
{
strings:
	$a0 = { 3c19c8eafbadd8575400685872f1b17d135c0ea28e2c3ef0d2346b53c7606e669cfe985bbe46e1480b958ed244960cd07a375c2cc0c28956c667cccc }


condition:
	$a0
}