rule Win_Trojan_Slam_1
{
strings:
	$a0 = { 579a38073801b83f0050bf44001e579ab4001501833e6202007557c6069b00008dbe00ff }


condition:
	$a0
}