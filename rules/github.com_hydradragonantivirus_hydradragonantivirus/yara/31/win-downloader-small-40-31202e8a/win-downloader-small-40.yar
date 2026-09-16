rule Win_Downloader_Small_40
{
strings:
	$a0 = { 3222bb7cb3ff14772f3132333934343c2b0bc026ecdd70726984bb334f1bb081641d32870a277d73d9ed6fb434325f2e536f6674777f }


condition:
	$a0
}