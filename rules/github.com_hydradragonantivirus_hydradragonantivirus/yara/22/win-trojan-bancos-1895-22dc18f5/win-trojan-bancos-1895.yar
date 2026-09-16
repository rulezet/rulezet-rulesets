rule Win_Trojan_Bancos_1895
{
strings:
	$a0 = { dd033f48bc6ea4794a696f9c7da950ca97ab73ddfb6de13c906b7a43822aae30399758e32b9d6e42b16cabb768f4fd5c3603aeb2b353c5fcf01fe706f2a59fcc913ab07c5635 }


condition:
	$a0
}