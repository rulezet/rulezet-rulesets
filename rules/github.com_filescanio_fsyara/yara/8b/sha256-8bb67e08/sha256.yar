rule SHA256 : hardened
{
	meta:
		description = "Uses constants related to SHA256"
		author = "Ivan Kwiatkowski (@JusticeRage)"

	strings:
		$sha256_init0 = { 67 E6 09 6A }
		$sha256_init1 = { 85 AE 67 BB }
		$sha256_init2 = { 72 F3 6E 3C }
		$sha256_init3 = { 3A F5 4F A5 }
		$sha256_init4 = { 7F 52 0E 51 }
		$sha256_init5 = { 8C 68 05 9B }
		$sha256_init6 = { AB D9 83 1F }
		$sha256_init7 = { 19 CD E0 5B }
		$sha256_k0 = { 98 2F 8A 42 }
		$sha256_k1 = { 91 44 37 71 }
		$sha256_k2 = { CF FB C0 B5 }
		$sha256_k3 = { A5 DB B5 E9 }
		$sha256_k4 = { 5B C2 56 39 }
		$sha256_k5 = { F1 11 F1 59 }
		$sha256_k6 = { A4 82 3F 92 }
		$sha256_k7 = { D5 5E 1C AB }
		$sha256_k8 = { 98 AA 07 D8 }
		$sha256_k9 = { 01 5B 83 12 }
		$sha256_k10 = { BE 85 31 24 }
		$sha256_k11 = { C3 7D 0C 55 }
		$sha256_k12 = { 74 5D BE 72 }
		$sha256_k13 = { FE B1 DE 80 }
		$sha256_k14 = { A7 06 DC 9B }
		$sha256_k15 = { 74 F1 9B C1 }
		$sha256_k16 = { C1 69 9B E4 }
		$sha256_k17 = { 86 47 BE EF }
		$sha256_k18 = { C6 9D C1 0F }
		$sha256_k19 = { CC A1 0C 24 }
		$sha256_k20 = { 6F 2C E9 2D }
		$sha256_k21 = { AA 84 74 4A }
		$sha256_k22 = { DC A9 B0 5C }
		$sha256_k23 = { DA 88 F9 76 }
		$sha256_k24 = { 52 51 3E 98 }
		$sha256_k25 = { 6D C6 31 A8 }
		$sha256_k26 = { C8 27 03 B0 }
		$sha256_k27 = { C7 7F 59 BF }
		$sha256_k28 = { F3 0B E0 C6 }
		$sha256_k29 = { 47 91 A7 D5 }
		$sha256_k30 = { 51 63 CA 06 }
		$sha256_k31 = { 67 29 29 14 }
		$sha256_k32 = { 85 0A B7 27 }
		$sha256_k33 = { 38 21 1B 2E }
		$sha256_k34 = { FC 6D 2C 4D }
		$sha256_k35 = { 13 0D 38 53 }
		$sha256_k36 = { 54 73 0A 65 }
		$sha256_k37 = { BB 0A 6A 76 }
		$sha256_k38 = { 2E C9 C2 81 }
		$sha256_k39 = { 85 2C 72 92 }
		$sha256_k40 = { A1 E8 BF A2 }
		$sha256_k41 = { 4B 66 1A A8 }
		$sha256_k42 = { 70 8B 4B C2 }
		$sha256_k43 = { A3 51 6C C7 }
		$sha256_k44 = { 19 E8 92 D1 }
		$sha256_k45 = { 24 06 99 D6 }
		$sha256_k46 = { 85 35 0E F4 }
		$sha256_k47 = { 70 A0 6A 10 }
		$sha256_k48 = { 16 C1 A4 19 }
		$sha256_k49 = { 08 6C 37 1E }
		$sha256_k50 = { 4C 77 48 27 }
		$sha256_k51 = { B5 BC B0 34 }
		$sha256_k52 = { 4A AA D8 4E }
		$sha256_k53 = { 4F CA 9C 5B }
		$sha256_k54 = { F3 6F 2E 68 }
		$sha256_k55 = { EE 82 8F 74 }
		$sha256_k56 = { 6F 63 A5 78 }
		$sha256_k57 = { 14 78 C8 84 }
		$sha256_k58 = { 08 02 C7 8C }
		$sha256_k59 = { FA FF BE 90 }
		$sha256_k60 = { EB 6C 50 A4 }
		$sha256_k61 = { F7 A3 F9 BE }
		$sha256_k62 = { F2 78 71 C6 }

	condition:
		all of ( $sha256_init* ) or 20 of ( $sha256_k* )
}