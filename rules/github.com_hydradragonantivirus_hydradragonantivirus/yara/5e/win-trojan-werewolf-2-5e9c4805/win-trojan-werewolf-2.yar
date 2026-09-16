rule Win_Trojan_WereWolf_2
{
strings:
	$a0 = { b430cd213c06770d3c037209b20db88702cd21733bbf00ff33fdbedc06572e803e98054575238cc00510002e01 }


condition:
	$a0
}