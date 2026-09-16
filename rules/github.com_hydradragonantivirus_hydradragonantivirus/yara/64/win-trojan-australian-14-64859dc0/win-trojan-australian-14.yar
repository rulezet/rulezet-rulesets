rule Win_Trojan_Australian_14
{
strings:
	$a0 = { bd0a008db6d501bf000157a5a4b8a054cd213d0b127426b844008ec0bf00018d33b91701f3a4061fb82135cd218c0656 }


condition:
	$a0
}