rule Win_Trojan_V_99
{
strings:
	$a0 = { ff1e0c00c33d0043741c3d014374203d004b745e80fc4f74303d06c674052eff2e0c00fec4cf }


condition:
	$a0
}