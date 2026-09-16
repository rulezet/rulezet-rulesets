rule Win_Trojan_Agent_35863
{
strings:
	$a0 = { b83000000090648b388b7f0c8b7f1c8b3f8b7f08e8000000005b81eb1910400089bbed1140008b }


condition:
	$a0
}