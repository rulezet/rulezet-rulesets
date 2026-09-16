rule Win_Trojan_VGEN_329
{
strings:
	$a0 = { 3dba9c02cd2193b43fb90001bab406cd21beb4060336cc06813cdca7754fa0c8063a0674017446e8b50033c9ba14 }


condition:
	$a0
}