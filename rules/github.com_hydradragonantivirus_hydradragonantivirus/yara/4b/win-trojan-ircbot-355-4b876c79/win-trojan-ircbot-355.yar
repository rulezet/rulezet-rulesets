rule Win_Trojan_IRCBot_355
{
strings:
	$a0 = { 6342d7a5fbab44af706e31bfd39b417073290ef0c1af6c2a6a76c324b3d0e8c5ebf843a751766896b3ea6370f9e5298b20b3f06fc570f815d28840e51a43a5bdf1e6c59ce087bbf063a59b3da0ad70e2 }


condition:
	$a0
}