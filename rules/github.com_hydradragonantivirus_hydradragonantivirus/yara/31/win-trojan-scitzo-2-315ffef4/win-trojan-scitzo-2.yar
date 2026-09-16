rule Win_Trojan_Scitzo_2
{
strings:
	$a0 = { 9090909090b9ffffbe2106e2fb908cc88ed8be6e01b000b84f028bc88bc18bc88134000081eefeffe2f6eb42e81200b440b99c04ba69009c9a00000000 }


condition:
	$a0
}