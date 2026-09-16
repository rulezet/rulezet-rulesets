rule Win_Trojan_VGEN_188
{
strings:
	$a0 = { 90bd04008d8e8604ffd1f6dff6dfa8be80be1c4ea87898352c91ac512061f279346185e12cd558342ca140d558f82ca15c }


condition:
	$a0
}