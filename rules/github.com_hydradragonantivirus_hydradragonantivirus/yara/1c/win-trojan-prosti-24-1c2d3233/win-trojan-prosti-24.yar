rule Win_Trojan_Prosti_24
{
strings:
	$a0 = { 83ceff }

	$a1 = { 33c0c3 }

	$a2 = { 7408 }

	$a3 = { 5ec3 }

	$a4 = { ffc38bc0538bd8 }

	$a5 = { ff406cc3 }

	$a6 = { 5ec3 }

	$a7 = { 85f6740f }

	$a8 = { 33db }

	$a9 = { 2c027429 }

	$a10 = { 43eb01 }

	$a11 = { 6685f6742c }

	$a12 = { 663bfb7527 }

	$a13 = { 33db }

	$a14 = { 84d2751a }

	$a15 = { 7308 }

	$a16 = { 33c0be18274a00 }

	$a17 = { 7308 }

	$a18 = { e8d7ffffffc3 }

	$a19 = { 3b1375f4 }

	$a20 = { 668b00c3 }

	$a21 = { 5e5bc3 }

	$a22 = { 33c0c3 }

	$a23 = { 535684d27408 }

	$a24 = { 8b501485d27406 }

	$a25 = { e86f0bfdffc3 }

	$a26 = { 837e0c047e0f }

	$a27 = { 8bc7 }

	$a28 = { 33c05bc3 }

	$a29 = { 5f5e5bc3 }

	$a30 = { 33c05bc3 }

	$a31 = { 83c003 }

	$a32 = { 83c203 }

	$a33 = { 8941244683c154 }

	$a34 = { 3b73207cc1 }

	$a35 = { 5f5e5bc3 }

	$a36 = { 837b4000740f }

	$a37 = { 5e5bc3 }

	$a38 = { 33d28d4618eb08 }

	$a39 = { 33c0 }

	$a40 = { 03c943 }

	$a41 = { 803a00742f }

	$a42 = { 33c0 }

	$a43 = { 4883e802721e }

	$a44 = { 497465 }

	$a45 = { 3b43207ce4 }

	$a46 = { 837b2402750c }

	$a47 = { 8b4b283b4b24750f }

	$a48 = { 85c9750c }

	$a49 = { 8bc75f5e5bc3 }

	$a50 = { 8b70183bde7d04 }

	$a51 = { 8bf88bde }

	$a52 = { 668339007404 }

	$a53 = { 83e9017207 }

	$a54 = { 49742c }

	$a55 = { 83d200 }

	$a56 = { 3b5de87e1e }

	$a57 = { 894dd4 }

	$a58 = { 33db }

	$a59 = { 03d683f8307cdb }

	$a60 = { 3b73207c93 }

	$a61 = { 8bcb }

	$a62 = { 83c618438344240854 }

	$a63 = { b901000000 }

	$a64 = { 837c240c007419 }

	$a65 = { 33d28bc3e87a020000 }

	$a66 = { 8bf0 }

	$a67 = { 83f8667527 }

	$a68 = { 5e5bc3 }

	$a69 = { 668138ff007605 }

	$a70 = { ba020000008bc3e8defaffff5bc3 }

	$a71 = { 817b1cdcff00007f09 }

	$a72 = { 833b007d1c }

	$a73 = { 837c24143f750b }

	$a74 = { 833b007d0f }

	$a75 = { 8bc7 }

	$a76 = { 5a5f5e5bc3 }

	$a77 = { 33c9894b14 }

	$a78 = { 837b0c00756e }

	$a79 = { 8bc3e84cffffff }

	$a80 = { 81ffff000000751b }

	$a81 = { 33c05bc3 }

	$a82 = { 837dec007419 }

	$a83 = { 8b550852ffd08bd8 }

	$a84 = { 8bc35b5dc20400 }

	$a85 = { 2c027406 }

	$a86 = { 2c027412 }

	$a87 = { 04fd2c0a730c }

	$a88 = { 2c027429 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88
}