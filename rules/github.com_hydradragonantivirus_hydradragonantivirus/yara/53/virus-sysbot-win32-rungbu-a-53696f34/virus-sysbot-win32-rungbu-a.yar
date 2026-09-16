rule Virus_Sysbot_Win32_Rungbu_A {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Rungbu.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0754f361701b007d660ebbc46d8ae44e95fbf30d1d94c5900918005e8235cbfe"

  strings:
    $s1  = "X:\\Raven Team 2006 Present H5N1\\N-Gen\\RIP\\VB98\\VB6.OLB" fullword ascii
    $s2  = ".EXE :agent" fullword wide
    $s3  = "Error Getting Version Information" fullword wide
    $s4  = "OPERA THE FAST AND FURY OF MY FIST!" fullword ascii
    $s5  = "Duffy Duck say \"I'm infected doc\"" fullword ascii
    $s6  = "Flu burung, masa sich burungnya bisa flu? Tanya kenapa?" fullword ascii
    $s7  = "Microsoft Access 2008 version 1.0" fullword ascii
    $s8  = "So at the end of story they save the screen." fullword ascii
    $s9  = "Barang mewah kena pajak, nabung di bank tiap bulan potong pajak," fullword ascii
    $s10 = "(Raven codename DIP \"05062705056127019455\")" fullword ascii
    $s11 = "Mungkin karena para pejabat dan wakil rakyat otaknya juga sudah penuh dengan MSG," fullword ascii
    $s12 = "Atau mereka terpilih karena terpintar diantara yang terbodoh," fullword ascii
    $s13 = "Pantas bangsa Indonesia tidak bisa maju karena bangsanya bodoh." fullword ascii
    $s14 = "(RIP \"Rest in Peace\"/Constantine)" fullword ascii
    $s15 = "Orang bijak bayar pajak, takut pajak jadi pembajak." fullword ascii
    $s16 = "Kita sebagai mahasiswa dan masyarakat merasa terasingkan dari perhatian pemerintah." fullword ascii
    $s17 = "Masukan Nama orang sakti" fullword ascii
    $s18 = "Pemerintah sekarang ini lebih memilih uang uang dan uang." fullword ascii
    $s19 = "Cuma udara yang dihirup yang tidak kena pajak, namun sudah tercemar" fullword ascii
    $s20 = "Rupiah kebanyakan angka! (Okinawa)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}