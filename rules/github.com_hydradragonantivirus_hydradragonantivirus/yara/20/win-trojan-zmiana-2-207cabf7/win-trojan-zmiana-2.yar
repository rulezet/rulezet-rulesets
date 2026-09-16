rule Win_Trojan_Zmiana_2
{
strings:
	$a0 = { 60555dbb1b00565eb9b903519059572e8037e85f43509058e2f4 }


condition:
	$a0
}