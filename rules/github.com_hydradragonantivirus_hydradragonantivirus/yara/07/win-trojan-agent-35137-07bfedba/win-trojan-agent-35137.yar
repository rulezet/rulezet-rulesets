rule Win_Trojan_Agent_35137
{
strings:
	$a0 = { b52f4d37e74c9bec994df52caf8e2a57640ca361af41027a9b1000b270a5cfd6d94713ae8465fabea36d61cfd1cea0019e74802ac6cd819e8b0d0626197dde56edd023c5d5423e6420792fa65e7aa44e }


condition:
	$a0
}