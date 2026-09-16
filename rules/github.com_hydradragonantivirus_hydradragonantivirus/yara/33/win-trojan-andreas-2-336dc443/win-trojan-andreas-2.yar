rule Win_Trojan_Andreas_2
{
strings:
	$a0 = { 2ea30501e823018d160401b90300b440cd21722a33d22e89161c01e81601e8e2002e8b0e6a05 }


condition:
	$a0
}