rule Win_Dropper_Agent_35250
{
strings:
	$a0 = { 93a2550e62c7fddf3f36e68c08c4adb98cf243e75c246d2332106c48dec9fe74c7c0ff4937239c6d25d8e99a54e1dabc0f5afdaaa7db0fb2fcd2ae2c95ec4feaeb839d77662a5aa1fa776cbf4b293578 }


condition:
	$a0
}