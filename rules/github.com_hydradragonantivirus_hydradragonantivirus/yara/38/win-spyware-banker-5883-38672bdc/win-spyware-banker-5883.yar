rule Win_Spyware_Banker_5883
{
strings:
	$a0 = { 1080dfa32b5dfe4c0315639f481cc9893ab3325a43687fbdead7358c73ba4f9890087dabd518f569497abc8334a93286c9fc9bf6c9eb273adb8eb5fab2de4164f493a6bb }


condition:
	$a0
}