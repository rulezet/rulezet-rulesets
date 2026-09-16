rule Win_Trojan_Zelentsov_1
{
strings:
	$a0 = { 3e720200ff7420b440ba0d01b97b0190cd21b80042b90000ba0000cd21b440b90300ba7402cd21 }


condition:
	$a0
}