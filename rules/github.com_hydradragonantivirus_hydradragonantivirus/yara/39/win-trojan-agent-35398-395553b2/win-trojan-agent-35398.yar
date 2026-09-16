rule Win_Trojan_Agent_35398
{
strings:
	$a0 = { 525351505633f6570f849fffffff40b8b87a1f }

	$a1 = { 3a61614352656143da6861434b7061437172614373 }


condition:
	$a0 and $a1
}