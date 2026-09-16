rule Win_Trojan_Trojan_243
{
strings:
	$a0 = { ba0010ba00071577bb8a548310ba005d81edba00061eb8520000ffff434c7456b44abbffffcd2183eb4eb44a }


condition:
	$a0
}