rule Win_Trojan_Delf_2190
{
strings:
	$a0 = { df8d45fc4bc6a38127c3bb217e3bc3068a50b8ee81c40f7e0b6f71ff5006f68b84b2201000f853ec7a514b5d3f5ce9024c4bd1c7d128ebfca6e8ddf154539b0b138bce8d83941d03d855c8 }


condition:
	$a0
}