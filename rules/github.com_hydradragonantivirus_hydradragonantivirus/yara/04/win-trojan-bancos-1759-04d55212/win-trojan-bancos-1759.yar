rule Win_Trojan_Bancos_1759
{
strings:
	$a0 = { 0d12cfb6cf1fc30b37f219d94b4532c97cc4eed4559c657abbce87bc465321f3a5d390af23410ca49050f56846747e2caaa822d0a48982be3d8fa367b2d7d7caed3093dd2fbc }


condition:
	$a0
}