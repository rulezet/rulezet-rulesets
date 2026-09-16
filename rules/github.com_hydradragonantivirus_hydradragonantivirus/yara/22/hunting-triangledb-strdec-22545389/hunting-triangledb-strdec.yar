rule Hunting_Triangledb_Strdec {
    meta:
        author = "@captainGeech42"
        description = "Look for the string decryption routine code snippet leveraged in TriangleDB."
        date = "2024-01-05"
        version = "1"
        DaysofYARA = "5/100"
        reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
        hash = "fd9e97cfb55f9cfb5d3e1388f712edd952d902f23a583826ebe55e9e322f730f"
    strings:
                $c1 = {
                        A8 02 1B 8B
                        09 01 40 39
                        A9 C3 19 38
                        08 05 40 39
                        A8 D3 19 38
                        A0 93 01 D1
                        A1 83 01 D1
                        02 02 80 52
                        9B 65 01 94
                        A8 03 5A F8
                        1F 01 1C EB
                        A0 02 00 54
                        7B 0B 00 91
                        DA FD FF B4
                        08 00 19 4A
                        C8 6A 3A 38
        }

    condition:
        (
            uint32(0) == 0xfeedface or             uint32(0) == 0xcefaedfe or             uint32(0) == 0xfeedfacf or             uint32(0) == 0xcffaedfe or             uint32(0) == 0xcafebabe or             uint32(0) == 0xbebafeca            ) and (
            filesize < 2MB and
            all of them
        )
}