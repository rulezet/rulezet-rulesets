rule Win_Trojan_MIPT_5
{
strings:
	$a0 = { 5633f6505351525657061e2e8b3601015681ee55fc2e8b142e891600012e8a54022e88160201b4ffcd2180fcfd }


condition:
	$a0
}