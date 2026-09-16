rule Win_Trojan_Luce_2
{
strings:
	$a0 = { 070fd1b91964165fe3f93a329ca2fb4807e7f882d37ed54d0c5d05e7f872d37e8f4d015e9265035e }


condition:
	$a0
}