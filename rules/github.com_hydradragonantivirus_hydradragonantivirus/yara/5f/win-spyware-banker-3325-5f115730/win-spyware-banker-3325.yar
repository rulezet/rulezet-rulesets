rule Win_Spyware_Banker_3325
{
strings:
	$a0 = { 1a8a6b00161a5bdb1e7494fbed70c8cee8ccd57acafc0674197dde0c5e86e2269a60025842b0c20537637e0844f34b0f68687bc65a24282e22334433bd04bd0a7b6929ca1bde }


condition:
	$a0
}