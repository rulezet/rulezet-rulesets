rule Win_Trojan_CodeBreak_1
{
strings:
	$a0 = { 8b042d03003e89869905b8004233c933d2cd21b4408d969805b90300cd21eb03e94801b8024233 }


condition:
	$a0
}