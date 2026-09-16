rule Win_Trojan_Hupigon_752
{
strings:
	$a0 = { 905eb5a6528c751e7a7a07778fbbb489f2ce68d4de7d18f907dfb00faaae3a58e2d5646a5e542176f155e92ce666f127216167a2e3c9d2613e203eefd9f9076fdebc3d5bb5da59d83a6dcb5dd128 }


condition:
	$a0
}