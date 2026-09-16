rule Win_Trojan_Krautfre_1
{
strings:
	$a0 = { 3dba9e00cd218bd8b80057cd2183f900741fb45080ec10b9d700ba0001cd21b80157b90000cd }


condition:
	$a0
}