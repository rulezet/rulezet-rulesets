rule Win_Trojan_Bacuy_1
{
strings:
	$a0 = { cc0042006c002220 }

	$a1 = { ff252c114000 }

	$a2 = { ffe0 }

	$a3 = { a1842443000bc07402 }

	$a4 = { ffe0 }

	$a5 = { 6898464000 }

	$a6 = { ffe0 }

	$a7 = { 68e4464000 }

	$a8 = { ffe0 }

	$a9 = { 682c474000 }

	$a10 = { a1a82443000bc07402 }

	$a11 = { ffe0 }

	$a12 = { ffe0 }

	$a13 = { ffe0 }

	$a14 = { 68f8484000 }

	$a15 = { ffe0 }

	$a16 = { 6850494000 }

	$a17 = { a1e42443000bc07402 }

	$a18 = { ffe0 }

	$a19 = { 6898494000 }

	$a20 = { a1202543000bc07402 }

	$a21 = { ffe0 }

	$a22 = { 68ec4b4000 }

	$a23 = { ffe0 }

	$a24 = { 68784c4000 }

	$a25 = { a15c2543000bc07402 }

	$a26 = { 68544d4000 }

	$a27 = { ffe0 }

	$a28 = { 684c4f4000 }

	$a29 = { ffe0 }

	$a30 = { ffe0 }

	$a31 = { 68dc4f4000 }

	$a32 = { ffe0 }

	$a33 = { ffe0 }

	$a34 = { 6894504000 }

	$a35 = { ffe0 }

	$a36 = { 68d8504000 }

	$a37 = { a1c82543000bc07402 }

	$a38 = { 6880514000 }

	$a39 = { ffe0 }

	$a40 = { 68d0514000 }

	$a41 = { a1ec2543000bc07402 }

	$a42 = { ffe0 }

	$a43 = { 8b3d8c1140008d45e0508d4dcc68a45d400051ffd7508d55d068f44d400052ffd750e89a44fdff8bf8ffd633c03bfb8d4dcc8d55d00f94c05152f7d86a028bf8 }

	$a44 = { 8b45d83bc37408 }

	$a45 = { 50e89742fdffffd6 }

	$a46 = { 558bec8b55088b92e80000008b821403000050508b10ff520458c9c20400 }

	$a47 = { 558bec8b55088b92e80000008b825c0c000050508b10ff520458c9c20400 }

	$a48 = { 558bec8b55088b92e80000008b822810000050508b10ff520458c9c20400 }

	$a49 = { 558bec8b55088b92e8000000 }

	$a50 = { 558bec8b55088b92e80000008b8270190000 }

	$a51 = { 558bec8b55088b92e80000008b82d41b000050508b10ff520458c9c20400 }

	$a52 = { 55088b92e80000008b82f01d000050508b10ff520458c9c20400 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40 and $a41 and $a42 and $a43 and $a44 and $a45 and $a46 and $a47 and $a48 and $a49 and $a50 and $a51 and $a52
}