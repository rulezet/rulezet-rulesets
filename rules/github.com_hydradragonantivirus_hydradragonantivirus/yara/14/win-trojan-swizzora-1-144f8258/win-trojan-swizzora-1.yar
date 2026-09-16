rule Win_Trojan_SwizzorA_1
{
strings:
	$a0 = { 0068 }

	$a1 = { 33f6 }

	$a2 = { 0400 }

	$a3 = { 8bff }

	$a4 = { 3bde7405 }

	$a5 = { 0400 }

	$a6 = { 33c0 }

	$a7 = { 0400 }

	$a8 = { 0400 }

	$a9 = { 0400 }

	$a10 = { 0400 }

	$a11 = { 8bff }

	$a12 = { 885f14 }

	$a13 = { 85f67405 }

	$a14 = { 0400 }

	$a15 = { 0400 }

	$a16 = { 3b16753d }

	$a17 = { 8937 }

	$a18 = { 890e }

	$a19 = { 0400 }

	$a20 = { 8b1b }

	$a21 = { 8b1b }

	$a22 = { 8bc3 }

	$a23 = { 8b1b }

	$a24 = { 33c0 }

	$a25 = { 6a24e8 }

	$a26 = { 0068 }

	$a27 = { 0400 }

	$a28 = { 33c0 }

	$a29 = { 0400 }

	$a30 = { 893e }

	$a31 = { 6a24e8 }

	$a32 = { 33c0 }

	$a33 = { 3bde7405 }

	$a34 = { 0068 }

	$a35 = { 33c0 }

	$a36 = { 0068 }

	$a37 = { 33c0 }

	$a38 = { 0400 }

	$a39 = { 0400 }

	$a40 = { 8b3febcd }

	$a41 = { 0400 }

	$a42 = { 0400 }

	$a43 = { 00e8 }

	$a44 = { 00c706 }

	$a45 = { 50e8 }

	$a46 = { 5ec3 }

	$a47 = { 8d470485c07405 }

	$a48 = { c20800 }

	$a49 = { 007407 }

	$a50 = { 00c706 }

	$a51 = { 53e8 }

	$a52 = { 00e8 }

	$a53 = { 040083c404 }

	$a54 = { 0400 }

	$a55 = { 0400 }

	$a56 = { 0085c0753d }

	$a57 = { 8bc8e8 }

	$a58 = { 005ec3 }

	$a59 = { 0068 }

	$a60 = { 56ff }

	$a61 = { 89780c8b4f }

	$a62 = { 56e8 }

	$a63 = { 6a18e8 }

	$a64 = { c74004 }

	$a65 = { 00eb02 }

	$a66 = { 33c0 }

	$a67 = { 85db742e }

	$a68 = { 5dc3 }

	$a69 = { ff15 }

	$a70 = { 33c0 }

	$a71 = { ff15 }

	$a72 = { 51ff15 }

	$a73 = { 0400 }

	$a74 = { 53e8 }

	$a75 = { 50e8 }

	$a76 = { 0400 }

	$a77 = { 0400 }

	$a78 = { 0400 }

	$a79 = { 0400 }

	$a80 = { 8d4900 }

	$a81 = { 0400 }

	$a82 = { 6aff68 }

	$a83 = { 0400 }

	$a84 = { 0400 }

	$a85 = { 33f6eb0a }

	$a86 = { 33c9eb08 }

	$a87 = { 33c0eb08 }

	$a88 = { 8bd18b09 }

	$a89 = { 8079150074ec }

	$a90 = { 737f }

	$a91 = { 3b067405 }

	$a92 = { 00c74604 }

	$a93 = { 00c701 }

	$a94 = { 894608 }

	$a95 = { 33c0 }

	$a96 = { 5f5e }

	$a97 = { 83c001 }

	$a98 = { 088b }

	$a99 = { 83c001 }

	$a100 = { 83c4 }

	$a101 = { 240c8d74 }

	$a102 = { 33c9 }

	$a103 = { 0128 }

	$a104 = { 5650ff15 }

	$a105 = { 55b9 }

	$a106 = { ffff }

	$a107 = { 8bd6 }

	$a108 = { 8dffff }

	$a109 = { 8b15 }

	$a110 = { 2bc2 }

	$a111 = { 008b500cb9 }

	$a112 = { 0033149d }

	$a113 = { 8b542414 }

	$a114 = { c74620 }

	$a115 = { 395f047705 }

	$a116 = { 5550e8 }

	$a117 = { ffff }

	$a118 = { 8bff }

	$a119 = { 03d8 }

	$a120 = { 33dbeb1f }

	$a121 = { 0400 }

	$a122 = { 0400 }

	$a123 = { 00e8 }

	$a124 = { 6aff68 }

	$a125 = { ffff }

	$a126 = { 6a40e801 }

	$a127 = { 6a50e881 }

	$a128 = { 33c0a3 }

	$a129 = { 3935 }

	$a130 = { 8325 }

	$a131 = { 8b0d }

	$a132 = { 390d }

	$a133 = { 33c0 }

	$a134 = { 6a03 }

	$a135 = { 7508 }

	$a136 = { 85c9742b }

	$a137 = { 7307 }

	$a138 = { 3b1d }

	$a139 = { 0f8cad000000 }

	$a140 = { 3bd07c08 }

	$a141 = { 7508 }

	$a142 = { 8b0d }

	$a143 = { 4a83cae042 }

	$a144 = { 33c0 }

	$a145 = { aba1 }

	$a146 = { 3c5a740a }

	$a147 = { 8ac3 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106 and $a107 and $a108 and $a109 and $a110 and $a111 and $a112 and $a113 and $a114 and $a115 and $a116 and $a117 and $a118 and $a119 and $a120 and $a121 and $a122 and $a123 and $a124 and $a125 and $a126 and $a127 and $a128 and $a129 and $a130 and $a131 and $a132 and $a133 and $a134 and $a135 and $a136 and $a137 and $a138 and $a139 and $a140 and $a141 and $a142 and $a143 and $a144 and $a145 and $a146 and $a147
}