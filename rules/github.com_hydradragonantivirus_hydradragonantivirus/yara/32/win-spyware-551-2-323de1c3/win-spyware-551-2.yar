rule Win_Spyware_551_2
{
strings:
	$a0 = { 9640e1bc6879ac08e1fdb23fecffd0e457a1582ae0ebb6a09cabb853a4f813d070cd84773af864b37fbae5bd0582bbedcbe9683a9cc7d196e7710c4cb713a8cef0c1552b8bc3af370160cc134eac }


condition:
	$a0
}