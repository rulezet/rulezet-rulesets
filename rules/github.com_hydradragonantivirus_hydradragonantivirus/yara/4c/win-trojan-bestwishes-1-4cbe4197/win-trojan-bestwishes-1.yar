rule Win_Trojan_BestWishes_1
{
strings:
	$a0 = { 4c00268c1e4e00071fb804008bf581ee }


condition:
	$a0
}