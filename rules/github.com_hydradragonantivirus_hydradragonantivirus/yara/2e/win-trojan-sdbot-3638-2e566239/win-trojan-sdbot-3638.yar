rule Win_Trojan_SdBot_3638
{
strings:
	$a0 = { fe096b76dde5b019e62779629ccc9c532b32da79a9b56cf0e41323b6ecc1084c153b646248d9be0815eac1cff882f15d47aa27e9cb7c72e97e5b2c4067a7ef67084dbf470ee120d68b45d2babc59 }


condition:
	$a0
}