rule Win_Spyware_Banker_2417
{
strings:
	$a0 = { 7d51e89585df78aa2b9d38570f11d553438c7c1d4d13bffb6edf1932d1d7ffc962a8a9fef50c1f433a589e1a737eec8f45854d80c1749d9b125e32cbab7054d749634d7fee673ad01c67 }


condition:
	$a0
}