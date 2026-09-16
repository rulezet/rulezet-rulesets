rule Win_Dropper_Agent_33655
{
strings:
	$a0 = { c4c7c7e201589b591c137272371171279944d32d4747d70a2ca3ff4c39537c41ce5db96ff36991b9edf8afdf3e5b062440e7dae79b1b354d325e51fd3eabaed1dcfa81be0674fc542aba47cae29db93d }


condition:
	$a0
}