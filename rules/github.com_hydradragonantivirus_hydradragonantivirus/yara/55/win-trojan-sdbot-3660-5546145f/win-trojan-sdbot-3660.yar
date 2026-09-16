rule Win_Trojan_SdBot_3660
{
strings:
	$a0 = { 4ca532727840dfcd281a5a84751b6ec7edbb8cbf2ad38dcc765cfc4d79387cd829967508a16fff7a37bfdc8471a345a503f161350f82cd9c09f80ee9a46c7097e69f8aa7bf4223d915394c5edf17 }


condition:
	$a0
}