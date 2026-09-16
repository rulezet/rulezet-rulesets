rule Win_Trojan_Neurobasher_2
{
strings:
	$a0 = { f7140d068181eefeffb44dcd2181fe5d12b4cd77068d06fabaebe5977fff3c8c979a8dd8cec6c6ccdfd0dfb89a8d929e9186dfc1c1c103d4004b0d32ec8db84b9d32de713cd400acb4712444 }


condition:
	$a0
}