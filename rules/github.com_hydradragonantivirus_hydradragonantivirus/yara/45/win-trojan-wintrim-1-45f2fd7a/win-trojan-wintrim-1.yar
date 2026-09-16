rule Win_Trojan_WinTrim_1
{
strings:
	$a0 = { 8d4164894148c3 }

	$a1 = { 8b466c33d2f7f1895670 }

	$a2 = { 8b460c33d2f7f1894660 }

	$a3 = { 8b4e2c5ff7d1894e185ec3 }

	$a4 = { 55568bf1578b6e248b4e288bc5d3e08b4e6c85c989465c740a }

	$a5 = { 85ff5b7409 }

	$a6 = { 8bc533d2f7f7894634 }

	$a7 = { 8b46445fd3e88946188b467483c0fc8946745e5dc3 }

	$a8 = { 8a41108a510102d0885101c3 }

	$a9 = { 8b41105e83c004894110c3 }

	$a10 = { 8b56748b46548b7e200bd18956708b562c2bc285ff89465c740a }

	$a11 = { 8b46648b561823d05f89564c8b565c0bd18b4e58d3e08956688946505ec3 }

	$a12 = { 8b464033d2f7f1894650 }

	$a13 = { dd4618dc1d60404500dfe0f6c4407509 }

	$a14 = { dd4138dc7148dd5918 }

	$a15 = { d94144dcc0d9592cc3 }

	$a16 = { 568bf18b460485c07413 }

	$a17 = { 8b4c240c8b5424085152ffd0c7460400000000 }

	$a18 = { 568b742408578d4eff8d861ae1ab6485c97408 }

	$a19 = { 8bf8 }

	$a20 = { 5f5ec3 }

	$a21 = { 8b44240450e8b6ffffff83c40448c3 }

	$a22 = { 8b4c2404b8f5f47261f7e18bc2c1e81d4985c97404 }

	$a23 = { 33d2f7f1 }

	$a24 = { 33d2f7f18bc2 }

	$a25 = { 33d2f7f1 }

	$a26 = { 5ec3 }

	$a27 = { 33d2f7f6 }

	$a28 = { 5f5e5bc3 }

	$a29 = { 8bc633d2f7f18bf2 }

	$a30 = { 8bc333d2f7f18bda }

	$a31 = { 57e800ffffff8bc883c40485c98bc37406 }

	$a32 = { 5f5e5bc3 }

	$a33 = { 8b4c2404b8d1e80f56f7e1568bf18bc2c1e61bc1e905c1e81e0bf17406 }

	$a34 = { 33d2f7f68bc2 }

	$a35 = { 5ec3 }

	$a36 = { 33d2f7f1 }

	$a37 = { 33d2f7f18bc2 }

	$a38 = { 5f5ec3 }

	$a39 = { 8bc633d2f7f18bf0 }

	$a40 = { 8bc633d2f7f15f5e8d42ffc3 }


condition:
	$a0 and $a1 and $a2 and $a3 and $a4 and $a5 and $a6 and $a7 and $a8 and $a9 and $a10 and $a11 and $a12 and $a13 and $a14 and $a15 and $a16 and $a17 and $a18 and $a19 and $a20 and $a21 and $a22 and $a23 and $a24 and $a25 and $a26 and $a27 and $a28 and $a29 and $a30 and $a31 and $a32 and $a33 and $a34 and $a35 and $a36 and $a37 and $a38 and $a39 and $a40
}