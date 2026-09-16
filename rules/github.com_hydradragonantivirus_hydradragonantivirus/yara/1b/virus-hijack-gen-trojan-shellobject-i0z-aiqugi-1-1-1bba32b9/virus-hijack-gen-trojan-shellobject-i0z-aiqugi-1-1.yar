rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74cf0cd3c6d97651a240bdcadef58f88a9f56e06ceaf9b247777a023a81583b4"

  strings:
    $s1  = "SELECT nama,nokp,jantina,kodkursus,semester,sesi,tempoh,penjaga,alamat,telefon,hubungan FROM pelajar WHERE ndp = '%" fullword wide
    $s2  = "insert into pelajar(ndp,nama,nokp,jantina,kodkursus,semester,sesi,tempoh,penjaga,alamat,telefon,hubungan,biaya) values(@a,@b,@c," wide
    $s3  = "update pelajar set ndp=@a,nama=@b,nokp=@c,jantina=@d,kodkursus=@e,semester=@f,sesi=@g,tempoh=@h,penjaga=@i,alamat=@j,telefon=@k," wide
    $s4  = "SELECT ID,ndp,nama,nokp,jantina,kodkursus,semester,sesi,tempoh,biaya,penjaga,alamat,telefon,hubungan FROM pelajar WHERE ndp LIKE" wide
    $s5  = "SELECT ID,ndp,nama,nokp,jantina,kodkursus,semester,sesi,tempoh,biaya,penjaga,alamat,telefon,hubungan FROM pelajar" fullword wide
    $s6  = "Anda Berjaya Log In" fullword wide
    $s7  = "SELECT * FROM a21" fullword wide
    $s8  = "SELECT * FROM a22" fullword wide
    $s9  = "SELECT * FROM a23" fullword wide
    $s10 = "SELECT * FROM a24" fullword wide
    $s11 = "SELECT * FROM a25" fullword wide
    $s12 = "SELECT * FROM a26" fullword wide
    $s13 = "SELECT * FROM a27" fullword wide
    $s14 = "SELECT * FROM a28" fullword wide
    $s15 = "SELECT * FROM a29" fullword wide
    $s16 = "SELECT * FROM a210" fullword wide
    $s17 = "SELECT * FROM a211" fullword wide
    $s18 = "SELECT * FROM a212" fullword wide
    $s19 = "SELECT * FROM a213" fullword wide
    $s20 = "SELECT * FROM a214" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}