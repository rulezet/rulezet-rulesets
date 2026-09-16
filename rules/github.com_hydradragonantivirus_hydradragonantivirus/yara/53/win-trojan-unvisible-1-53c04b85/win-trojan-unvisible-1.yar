rule Win_Trojan_Unvisible_1
{
strings:
	$a0 = { 83eb172e891e2e058e0fffc3b9b000be2b33fff3a58e46f4ff788b4efae317b4488bd938168ec0 }


condition:
	$a0
}