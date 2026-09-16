rule crypto_vertical_transposition : info crypto {
	meta:
	        description = "Alphabet plaintext writtent in transposition cipher"
		

	strings:
		$s_topleft_01  = "AEIMQU"
		$s_topleft_02  = "BFJNRV"
		$s_topleft_03  = "CGKOSW"
		$s_topleft_04  = "DHLPTX"
		$s_topright_01 = "UQMIEA"
		$s_topright_02 = "VRNJFB"
		$s_topright_03 = "WSOKGC"
		$s_topright_04 = "XTPLHD"

		$sl_topleft_01  = "aeimqu"
		$sl_topleft_02  = "bfjnrv"
		$sl_topleft_03  = "cgkosw"
		$sl_topleft_04  = "dhlptx"
		$sl_topright_01 = "umqmiea"
		$sl_topright_02 = "vrnjfb"
		$sl_topright_03 = "wsokgc"
		$sl_topright_04 = "xtplhd"

	condition:
                4 of ($s_*) or 4 of ($sl_*)
}