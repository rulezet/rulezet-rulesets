rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_aWZUE8k_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@aWZUE8k_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "196a1830d37e6509ae6be4c2f704e1c24d3008e5f3f85e368fa4aed5fac7e5d1"

  strings:
    $s1 = "INSERT INTO henkilotiedot(etunimi, sukunimi, email, puhnumero, osoite, postinumero, postitoimipaikka)VALUES('" fullword wide
    $s2 = "SELECT * FROM henkilotiedot WHERE sukunimi='" fullword wide
    $s3 = "SELECT * FROM projektitiedot WHERE projekti_nimi='" fullword wide
    $s4 = "SELECT * FROM henkilotiedot;" fullword wide
    $s5 = "SELECT * FROM projektitiedot" fullword wide
    $s6 = "SELECT * FROM tehtavat" fullword wide
    $s7 = "INSERT INTO projektitiedot(projekti_nimi, aloituspvm, kuvaus)VALUES('" fullword wide
    $s8 = "INSERT INTO tehtavat(tehtava_nimi, tehtava_kuvaus)VALUES('" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}