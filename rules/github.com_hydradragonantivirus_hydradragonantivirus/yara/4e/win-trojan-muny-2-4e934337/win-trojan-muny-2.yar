rule Win_Trojan_Muny_2
{
strings:
	$a0 = { 5e81ee05018c942e0189a43001160e179c58f6c401741a58ffe0e66433c9e2feb430cd21a1 }


condition:
	$a0
}