rule Win_Trojan_Invader_4
{
strings:
	$a0 = { 5d83ed032e898639002e899e3b002ec7863d000000ebd2bb0000b80335cd2183fb00750dcd }


condition:
	$a0
}