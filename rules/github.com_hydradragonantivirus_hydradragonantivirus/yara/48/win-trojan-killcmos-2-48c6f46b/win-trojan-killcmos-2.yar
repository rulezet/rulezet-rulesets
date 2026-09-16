rule Win_Trojan_KillCMOS_2
{
strings:
	$a0 = { cd21b93e00ba3800b440cd21b8004ccd21436f707972696768742028432920576561726e6573 }


condition:
	$a0
}