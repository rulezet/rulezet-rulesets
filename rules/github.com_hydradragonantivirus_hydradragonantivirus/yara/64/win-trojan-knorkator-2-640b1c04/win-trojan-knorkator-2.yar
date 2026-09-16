rule Win_Trojan_Knorkator_2
{
strings:
	$a0 = { b801faba4559cd16b802febe414ebf554ecd2fb42acd213c057525b42acd2180fa15751cb409ba????cd21b439ba????cd21b439ba????cd21b439ba????cd21 }


condition:
	$a0
}