rule Win_Trojan_Mephisto_12
{
strings:
	$a0 = { 1501b979018bb60a0431354747cce2f959c3cd21e8e6ffe9c6fd }


condition:
	$a0
}