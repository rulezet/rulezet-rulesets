rule Win_Trojan_SdBot_3692
{
strings:
	$a0 = { 75cdf89335ec3cbece41e6614d19df1db8fce0736462756b11f1f0f87391c49e2cdb5b304db0e98fea5de4ab04c70f56addd1c2c2a627c8479a3ce97fd56a6ba0b08028b1afa0b7fb7a9d4fda9ae }


condition:
	$a0
}