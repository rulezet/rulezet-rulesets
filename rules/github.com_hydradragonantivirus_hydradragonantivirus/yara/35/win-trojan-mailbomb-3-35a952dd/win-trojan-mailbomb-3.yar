rule Win_Trojan_Mailbomb_3
{
strings:
	$a0 = { 612e66726f6d3d2262696c6c5f6761746573406d6963726f736f66742e636f6d }

	$a1 = { 406176702e7275 }

	$a2 = { 796f7562617374617264 }


condition:
	$a0 and $a1 and $a2
}