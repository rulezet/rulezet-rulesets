rule Win_Trojan_Swizzor_607
{
strings:
	$a0 = { 0068 }

	$a1 = { 6aff68 }

	$a2 = { 00c74604 }

	$a3 = { 3bc98b59047409 }

	$a4 = { 8bff }

	$a5 = { 33c0 }

	$a6 = { 897704 }

	$a7 = { 897704 }

	$a8 = { 8b3b }

	$a9 = { ff15 }

	$a10 = { 7666 }

	$a11 = { 8b1b }

	$a12 = { 897708 }

	$a13 = { 8956088931 }

	$a14 = { 8937eb03 }

	$a15 = { 897708 }

	$a16 = { e873c50400 }

	$a17 = { 3bc77405 }

	$a18 = { 8b1b }

	$a19 = { 8b1b }

	$a20 = { 33c0 }

	$a21 = { 33c0 }

	$a22 = { 6aff68 }

	$a23 = { 8b4510eb02 }

	$a24 = { 33c0 }

	$a25 = { e8f5db0400 }

	$a26 = { 6a0068 }

	$a27 = { 33c0 }

	$a28 = { 6a0068 }

	$a29 = { 0068 }

	$a30 = { 0068 }

	$a31 = { 0068 }

	$a32 = { 33c0 }

	$a33 = { 00c703 }

	$a34 = { e8b1d20400 }

	$a35 = { 00c706 }

	$a36 = { 007509 }

	$a37 = { 00c74604 }

	$a38 = { 5ec3 }

	$a39 = { c20800 }

	$a40 = { 6a1068 }

	$a41 = { 00c706 }

	$a42 = { 8bc6 }

	$a43 = { 89780c }

	$a44 = { 8bc38d5001eb03 }

	$a45 = { 00c3 }

	$a46 = { 33f6 }

	$a47 = { 83460804 }

	$a48 = { 56c706 }

	$a49 = { ff15 }

	$a50 = { 8d6e2855ff15 }

	$a51 = { bb19fcffff }

	$a52 = { 0055ff15 }

	$a53 = { e879af0400 }

	$a54 = { 56ff15 }

	$a55 = { 85db7505 }

	$a56 = { 33c0eb08 }

	$a57 = { e84bac0400 }

	$a58 = { 895c2420 }

	$a59 = { 8b3f }

	$a60 = { e89ea80400 }

	$a61 = { 6aff68 }

	$a62 = { 85ed7505 }

	$a63 = { 1bc083d8ff }

	$a64 = { 8b3feb88 }

	$a65 = { 008bc65ec21400 }

	$a66 = { 6aff68 }

	$a67 = { 39710c7305 }

	$a68 = { 3b067405 }

	$a69 = { 33c0 }

	$a70 = { 8bf3 }

	$a71 = { 33c9 }

	$a72 = { 0128 }

	$a73 = { e842610000 }

	$a74 = { 5f5ec3 }

	$a75 = { 3bc27d02 }

	$a76 = { 6857000780e8c88bffff }

	$a77 = { 8b15 }

	$a78 = { 2bc2 }

	$a79 = { 6aff68 }

	$a80 = { 8b500cb9 }

	$a81 = { 8bfec1ef05 }

	$a82 = { f6c210754b }

	$a83 = { c74624 }

	$a84 = { 833f0b7506 }

	$a85 = { 83c601eb0d }

	$a86 = { 83c603eb03 }

	$a87 = { 33ed }

	$a88 = { 0fb73e2bc785c07e11 }

	$a89 = { 8b742450 }

	$a90 = { 8bff }

	$a91 = { 85ed7404 }

	$a92 = { 6aff68 }

	$a93 = { 6aff68 }

	$a94 = { 6aff68 }

	$a95 = { 33c0a3 }

	$a96 = { 8d4900 }

	$a97 = { 00ba }

	$a98 = { 00c3 }

	$a99 = { 8b0d }

	$a100 = { 00c3 }

	$a101 = { 00c3 }

	$a102 = { 00c3 }

	$a103 = { ffd0 }

	$a104 = { 5f5ec3 }

	$a105 = { 0057a3 }

	$a106 = { 390d }

	$a107 = { 33c0 }

	$a108 = { 33c0 }

	$a109 = { 6a03 }

	$a110 = { 85c9742b }

	$a111 = { 7508 }

	$a112 = { 4083f8037cf3 }

	$a113 = { 33ff47 }

	$a114 = { 89318bcf }

	$a115 = { 4879de }

	$a116 = { 8b0d }

	$a117 = { 3bd07c08 }

	$a118 = { 83fe01 }

	$a119 = { 8b35 }

	$a120 = { 4879de }

	$a121 = { 01ba }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106 and $a107 and $a108 and $a109 and $a110 and $a111 and $a112 and $a113 and $a114 and $a115 and $a116 and $a117 and $a118 and $a119 and $a120 and $a121
}