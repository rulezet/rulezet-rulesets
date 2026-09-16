rule Win_Trojan_Bombole_1
{
strings:
	$a0 = { b90000ba0000cd211f619de91eff5b424f4d424f4c452076312e335d20627920474f424c4545 }


condition:
	$a0
}