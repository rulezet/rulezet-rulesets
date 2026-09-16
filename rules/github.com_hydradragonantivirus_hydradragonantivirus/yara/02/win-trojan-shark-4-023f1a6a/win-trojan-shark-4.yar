rule Win_Trojan_Shark_4
{
strings:
	$a0 = { 8ed8b409ba0000cd21b218e83100e82e00e82b00fec280fa0175f0b409ba7e00cd21beee00e8 }


condition:
	$a0
}