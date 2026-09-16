rule Win_Adware_Multiplug_5
{
strings:
	$a0 = { efbbbf3c21444f4354595045 }

	$a1 = { 68746d6c3e[0-2]3c68746d6c3e[0-2]3c686561643e }

	$a2 = { 3c7374796c65 }

	$a3 = { 747970653d22746578742f637373223e }

	$a4 = { 626f6479207b }

	$a5 = { 6865696768743a }

	$a6 = { 333070783b }

	$a7 = { 0977696474683a }

	$a8 = { 32353070783b }

	$a9 = { 6261636b67726f756e643a }

	$a10 = { 677261793b }

	$a11 = { 6f766572666c6f773a68696464656e3b }

	$a12 = { 3c2f7374796c }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12
}