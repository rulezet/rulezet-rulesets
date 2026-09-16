rule Win_Dropper_Agent_35870
{
strings:
	$a0 = { 558bec5b5357568b?5080000008bb50c000000c1ee028bbd10000000[16-64]044e0f85??ffffff5e5f5bc9c20c00 }


condition:
	$a0
}