rule Win_Trojan_Bancos_824
{
strings:
	$a0 = { 78de7b331df4874bd17e07a2fb5e427bcef1be8715c0e2e83cbf2cd4797f2bf75c10f8e2467c67c67c67c67c7f5390d17df74dc1f49f0ff6c086fe0f5ff9605fb7da7f1df525f9bdef80f1 }


condition:
	$a0
}