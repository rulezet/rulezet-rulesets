rule Win_Trojan_Wang_1
{
strings:
	$a0 = { 3e720434128cc88ed8754f803e0000ff7422803e000000 }


condition:
	$a0
}