rule Win_Spyware_Banker_2683
{
strings:
	$a0 = { 206ab8b550dffc1492ae81bc7a5134fed35e611ba72e639ad66b050aa706ad5e6e92cb3db690b1838b555b36cfacded006c6e7bb857dc96e8eda4048ec02e426f9759ca8e370c018f0634b }


condition:
	$a0
}