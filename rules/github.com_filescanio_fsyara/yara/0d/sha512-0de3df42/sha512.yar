rule SHA512 : hardened
{
	meta:
		description = "Uses constants related to SHA512"
		author = "Ivan Kwiatkowski (@JusticeRage)"

	strings:
		$sha512_k1 = { 22 AE 28 D7 98 2F 8A 42 }
		$sha512_k2 = { CD 65 EF 23 91 44 37 71 }
		$sha512_k3 = { 2F 3B 4D EC CF FB C0 B5 }
		$sha512_k4 = { BC DB 89 81 A5 DB B5 E9 }
		$sha512_k5 = { 38 B5 48 F3 5B C2 56 39 }
		$sha512_k6 = { 19 D0 05 B6 F1 11 F1 59 }
		$sha512_k7 = { 9B 4F 19 AF A4 82 3F 92 }
		$sha512_k8 = { 18 81 6D DA D5 5E 1C AB }
		$sha512_k9 = { 42 02 03 A3 98 AA 07 D8 }
		$sha512_k10 = { BE 6F 70 45 01 5B 83 12 }
		$sha512_k11 = { 8C B2 E4 4E BE 85 31 24 }
		$sha512_k12 = { E2 B4 FF D5 C3 7D 0C 55 }
		$sha512_k13 = { 6F 89 7B F2 74 5D BE 72 }
		$sha512_k14 = { B1 96 16 3B FE B1 DE 80 }
		$sha512_k15 = { 35 12 C7 25 A7 06 DC 9B }
		$sha512_k16 = { 94 26 69 CF 74 F1 9B C1 }
		$sha512_k17 = { D2 4A F1 9E C1 69 9B E4 }
		$sha512_k18 = { E3 25 4F 38 86 47 BE EF }
		$sha512_k19 = { B5 D5 8C 8B C6 9D C1 0F }
		$sha512_k20 = { 65 9C AC 77 CC A1 0C 24 }
		$sha512_k21 = { 75 02 2B 59 6F 2C E9 2D }
		$sha512_k22 = { 83 E4 A6 6E AA 84 74 4A }
		$sha512_k23 = { D4 FB 41 BD DC A9 B0 5C }
		$sha512_k24 = { B5 53 11 83 DA 88 F9 76 }
		$sha512_k25 = { AB DF 66 EE 52 51 3E 98 }
		$sha512_k26 = { 10 32 B4 2D 6D C6 31 A8 }
		$sha512_k27 = { 3F 21 FB 98 C8 27 03 B0 }
		$sha512_k28 = { E4 0E EF BE C7 7F 59 BF }
		$sha512_k29 = { C2 8F A8 3D F3 0B E0 C6 }
		$sha512_k30 = { 25 A7 0A 93 47 91 A7 D5 }
		$sha512_k31 = { 6F 82 03 E0 51 63 CA 06 }
		$sha512_k32 = { 70 6E 0E 0A 67 29 29 14 }
		$sha512_k33 = { FC 2F D2 46 85 0A B7 27 }
		$sha512_k34 = { 26 C9 26 5C 38 21 1B 2E }
		$sha512_k35 = { ED 2A C4 5A FC 6D 2C 4D }
		$sha512_k36 = { DF B3 95 9D 13 0D 38 53 }
		$sha512_k37 = { DE 63 AF 8B 54 73 0A 65 }
		$sha512_k38 = { A8 B2 77 3C BB 0A 6A 76 }
		$sha512_k39 = { E6 AE ED 47 2E C9 C2 81 }
		$sha512_k40 = { 3B 35 82 14 85 2C 72 92 }
		$sha512_k41 = { 64 03 F1 4C A1 E8 BF A2 }
		$sha512_k42 = { 01 30 42 BC 4B 66 1A A8 }
		$sha512_k43 = { 91 97 F8 D0 70 8B 4B C2 }
		$sha512_k44 = { 30 BE 54 06 A3 51 6C C7 }
		$sha512_k45 = { 18 52 EF D6 19 E8 92 D1 }
		$sha512_k46 = { 10 A9 65 55 24 06 99 D6 }
		$sha512_k47 = { 2A 20 71 57 85 35 0E F4 }
		$sha512_k48 = { B8 D1 BB 32 70 A0 6A 10 }
		$sha512_k49 = { 53 AB 41 51 08 6C 37 1E }
		$sha512_k50 = { 99 EB 8E DF 4C 77 48 27 }
		$sha512_k51 = { A8 48 9B E1 B5 BC B0 34 }
		$sha512_k52 = { 63 5A C9 C5 B3 0C 1C 39 }
		$sha512_k53 = { CB 8A 41 E3 4A AA D8 4E }
		$sha512_k54 = { 73 E3 63 77 4F CA 9C 5B }
		$sha512_k55 = { A3 B8 B2 D6 F3 6F 2E 68 }
		$sha512_k56 = { FC B2 EF 5D EE 82 8F 74 }
		$sha512_k57 = { 60 2F 17 43 6F 63 A5 78 }
		$sha512_k58 = { 72 AB F0 A1 14 78 C8 84 }
		$sha512_k59 = { EC 39 64 1A 08 02 C7 8C }
		$sha512_k60 = { 28 1E 63 23 FA FF BE 90 }
		$sha512_k61 = { E9 BD 82 DE EB 6C 50 A4 }
		$sha512_k62 = { 15 79 C6 B2 F7 A3 F9 BE }
		$sha512_k63 = { 2B 53 72 E3 F2 78 71 C6 }
		$sha512_k64 = { 9C 61 26 EA CE 3E 27 CA }
		$sha512_k65 = { 07 C2 C0 21 C7 B8 86 D1 }
		$sha512_k66 = { 1E EB E0 CD D6 7D DA EA }
		$sha512_k67 = { 78 D1 6E EE 7F 4F 7D F5 }
		$sha512_k68 = { BA 6F 17 72 AA 67 F0 06 }
		$sha512_k69 = { A6 98 C8 A2 C5 7D 63 0A }
		$sha512_k70 = { AE 0D F9 BE 04 98 3F 11 }
		$sha512_k71 = { 1B 47 1C 13 35 0B 71 1B }
		$sha512_k72 = { 84 7D 04 23 F5 77 DB 28 }
		$sha512_k73 = { 93 24 C7 40 7B AB CA 32 }
		$sha512_k74 = { BC BE C9 15 0A BE 9E 3C }
		$sha512_k75 = { 4C 0D 10 9C C4 67 1D 43 }
		$sha512_k76 = { B6 42 3E CB BE D4 C5 4C }
		$sha512_k77 = { 2A 7E 65 FC 9C 29 7F 59 }
		$sha512_k78 = { EC FA D6 3A AB 6F CB 5F }
		$sha512_k79 = { 17 58 47 4A 8C 19 44 6C }

	condition:
		30 of ( $sha512_k* )
}