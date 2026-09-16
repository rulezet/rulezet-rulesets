rule Win_Trojan_Agent_32809
{
strings:
	$a0 = { a338f3b8e70c8072def00bf63d4cc61ac182ec8ddf614a29556559555a1a3e5aabe5065a834762c091b8482b35d6cc06470b77ab9180b165422b331aefd68b7faa }


condition:
	$a0
}