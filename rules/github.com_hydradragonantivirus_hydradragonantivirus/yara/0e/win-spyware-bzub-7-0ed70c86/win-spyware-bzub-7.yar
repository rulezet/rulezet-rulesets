rule Win_Spyware_Bzub_7
{
strings:
	$a0 = { 8b3d4c104000687c124000ffd7686c124000ffd7bbd8000000bf3846400053578bcee8c9dbffff }


condition:
	$a0
}