rule Win_Trojan_OneHalf_6
{
strings:
	$a0 = { 39c58ad655f3de4a6b47c5cce420ad19cd0ed60e5f3830f6e8fda7da9aa53160d900547052da00a3aeabbd5a27d5f5c8 }


condition:
	$a0
}