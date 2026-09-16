rule Win_Trojan_Fraudload_34
{
strings:
	$a0 = { b067b8aab0c5f1aa26b7b81a51dc50abb0a1b8aab0040f50b1dcb7aab054b80bb734b8aab02f3fab95dcb7de7bdc33d25f9d8cabb0dce7dcfa4774006100553100006b6168646b6a6969747761 }


condition:
	$a0
}