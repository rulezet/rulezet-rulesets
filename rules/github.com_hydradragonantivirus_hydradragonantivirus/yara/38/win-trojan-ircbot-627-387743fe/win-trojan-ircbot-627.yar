rule Win_Trojan_IRCBot_627
{
strings:
	$a0 = { e51c76d75eb122406979e5cac7f82c75f029cfbc7fc4215a4e89d803e7e3a50b67c19a9017cbd66cf0e35338f01300dae2003979c4bf05b4b4e3fc35996873638d1fb3a6ef4f912a3cc24ef8ac2c }


condition:
	$a0
}