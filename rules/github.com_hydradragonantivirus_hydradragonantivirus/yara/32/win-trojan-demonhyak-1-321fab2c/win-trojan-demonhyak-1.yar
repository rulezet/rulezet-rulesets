rule Win_Trojan_Demonhyak_1
{
strings:
	$a0 = { b44eb90b11cd21907302eb11e84700ba8000b44fcd21907302eb02ebefb42acd213c027404b44ccd21c606bc0100eb00a0bd01b9a000ba0000bb0000cd }


condition:
	$a0
}