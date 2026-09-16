rule Win_Trojan_Havoc_6
{
strings:
	$a0 = { fc8cc8ba980203d052ba0c0152bab20103c28bd805ff008edb8ec033f633ffb90800f3a54b484a79ee8ed88ec3be47 }


condition:
	$a0
}