rule Win_Trojan_SkinTrim_1
{
strings:
	$a0 = { 3c2d7504 }

	$a1 = { 3c617504 }

	$a2 = { 6a0f }

	$a3 = { c20400 }

	$a4 = { c20400 }

	$a5 = { 880343 }

	$a6 = { 895dec }

	$a7 = { 895dfc }

	$a8 = { 33ff }

	$a9 = { 8b07 }

	$a10 = { 3906740a }

	$a11 = { 8bf9 }

	$a12 = { 33c0eb35 }

	$a13 = { 8365f000 }

	$a14 = { c16df802 }

	$a15 = { 8b0850ff5104 }

	$a16 = { 895e34 }

	$a17 = { e8b8cdffff }

	$a18 = { 33c0 }

	$a19 = { c20400 }

	$a20 = { 395df87409 }

	$a21 = { 885e05eb03 }

	$a22 = { 3bf37407 }

	$a23 = { 8b0b8b3f }

	$a24 = { 498908 }

	$a25 = { 33c0 }

	$a26 = { 894638 }

	$a27 = { 32db }

	$a28 = { 6a015feb03 }

	$a29 = { 33c0eb1f }

	$a30 = { 894604 }

	$a31 = { 80fa807503 }

	$a32 = { 8b46088308ff }

	$a33 = { 8817 }

	$a34 = { 3bf77317 }

	$a35 = { 8b75e8 }

	$a36 = { 2b06 }

	$a37 = { 8bf3 }

	$a38 = { 48740c }

	$a39 = { 83450c04 }

	$a40 = { 8d410cc3 }

	$a41 = { 33c0 }

	$a42 = { 5f5e5bc9c3 }

	$a43 = { 5f5e5bc9c3 }

	$a44 = { 53ebd3 }

	$a45 = { 8b542408 }

	$a46 = { 39442408740c }

	$a47 = { 56eb1f }

	$a48 = { 6a0056ffd3 }

	$a49 = { 7603 }

	$a50 = { 8b45f8 }

	$a51 = { 5dc3 }

	$a52 = { 6a0158eb02 }

	$a53 = { c7450c01000000 }

	$a54 = { 3bfb0f8582000000 }

	$a55 = { 6a0158 }

	$a56 = { b301 }

	$a57 = { 8b5db4 }

	$a58 = { 33db }

	$a59 = { c20800 }

	$a60 = { c9c3 }

	$a61 = { 85f67461 }

	$a62 = { 6a0158 }

	$a63 = { 3bc37519 }

	$a64 = { 8bc65ec9c20400 }

	$a65 = { 33c0 }

	$a66 = { 33c0 }

	$a67 = { 33c0c9c3 }

	$a68 = { 83e857c3 }

	$a69 = { 5f5e5dc3 }

	$a70 = { 6a015e }

	$a71 = { 8bc6 }

	$a72 = { 83c8ff }

	$a73 = { 5ec3 }

	$a74 = { 8818 }

	$a75 = { 8818 }

	$a76 = { 395df07409 }

	$a77 = { 8945f4 }

	$a78 = { ff15247102105f5b }

	$a79 = { 5ec9c3 }

	$a80 = { 33c0 }

	$a81 = { 33c0 }

	$a82 = { 394d0c7c03 }

	$a83 = { 83fa0f7318 }

	$a84 = { 5f5e5bc3 }

	$a85 = { 894520 }

	$a86 = { 33d2 }

	$a87 = { 85d77406 }

	$a88 = { 5f5e }

	$a89 = { 33c0c3 }

	$a90 = { 85db740a }

	$a91 = { a808740c }

	$a92 = { 83450c04 }

	$a93 = { f6c440740f }

	$a94 = { 830908 }

	$a95 = { 8bf8 }

	$a96 = { 5f5e }

	$a97 = { 5ec3 }

	$a98 = { 8d4115c3 }

	$a99 = { 6a5758eb0b }

	$a100 = { 6a0d58eb41 }

	$a101 = { c20400 }

	$a102 = { 6a0d58eb21 }

	$a103 = { 6a0d58eb50 }

	$a104 = { 5ec9c20400 }

	$a105 = { c20400 }

	$a106 = { c20400 }

	$a107 = { c20400 }

	$a108 = { c20400 }

	$a109 = { c20400 }

	$a110 = { 395de87406 }

	$a111 = { 8d4f05 }

	$a112 = { 8b4df8 }

	$a113 = { 473b7d140f8c6effffff }

	$a114 = { 885dff }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52 and $a53 and $a54 and $a55 and $a56 and $a57 and $a58 and $a59 and $a60 and $a61 and $a62 and $a63 and $a64 and $a65 and $a66 and $a67 and $a68 and $a69 and $a70 and $a71 and $a72 and $a73 and $a74 and $a75 and $a76 and $a77 and $a78 and $a79 and $a80 and $a81 and $a82 and $a83 and $a84 and $a85 and $a86 and $a87 and $a88 and $a89 and $a90 and $a91 and $a92 and $a93 and $a94 and $a95 and $a96 and $a97 and $a98 and $a99 and $a100 and $a101 and $a102 and $a103 and $a104 and $a105 and $a106 and $a107 and $a108 and $a109 and $a110 and $a111 and $a112 and $a113 and $a114
}