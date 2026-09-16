rule Win_Trojan_CommFix_1
{
strings:
	$a0 = { 05008ed8bb0100b002b96400ba00008e5d378b5d63cd267202731cb91500ba3100b84000cd21b8 }


condition:
	$a0
}