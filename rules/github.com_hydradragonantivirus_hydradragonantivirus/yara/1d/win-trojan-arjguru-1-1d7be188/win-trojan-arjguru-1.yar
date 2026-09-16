rule Win_Trojan_ArjGuru_1
{
strings:
	$a0 = { d80510008ed8068e0601002e8c066da5bf2d00b020b91700f3aa2e8c1e9ea4b430cd213c057402eb57c706a3b7e9da }


condition:
	$a0
}