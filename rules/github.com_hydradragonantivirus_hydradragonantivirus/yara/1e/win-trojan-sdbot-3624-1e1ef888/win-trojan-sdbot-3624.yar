rule Win_Trojan_SdBot_3624
{
strings:
	$a0 = { 377e732e75890db37661c9f8b2b29b2b57748b45f12d96cfea100cf7595955da1cb6d991a983341db953dee597d19d632cbf04a94747bcc0e6427d34afa36efaebb48e1a36ad5fb6f2ab0a29fa11 }


condition:
	$a0
}