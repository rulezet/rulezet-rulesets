rule Win_Trojan_Trivial_350
{
strings:
	$a0 = { 023dcd2193e2f8061f8bd749b43fcd2103c2fecc910e075fa674054bb440cd214f4eb9b5fe0e1f }


condition:
	$a0
}