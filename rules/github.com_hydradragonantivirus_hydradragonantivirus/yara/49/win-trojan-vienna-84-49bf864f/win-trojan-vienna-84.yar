rule Win_Trojan_Vienna_84
{
strings:
	$a0 = { 02b440cd21721f33c933d2b80042cd217214b90300817cfe99017203b909018d540db440cd }


condition:
	$a0
}