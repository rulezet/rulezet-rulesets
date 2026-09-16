rule Win_Trojan_Gene_2
{
strings:
	$a0 = { 59fbe6c947afe11d641ee793eac96dc3d507c96fc3a1a1ae0c091c24e6e700007b061c01b94a00beff052ea04906fa83f900740c2e8a2432e02e88244649ebeffbc3e88effe8dcffc3e8d8ffe884ff }


condition:
	$a0
}