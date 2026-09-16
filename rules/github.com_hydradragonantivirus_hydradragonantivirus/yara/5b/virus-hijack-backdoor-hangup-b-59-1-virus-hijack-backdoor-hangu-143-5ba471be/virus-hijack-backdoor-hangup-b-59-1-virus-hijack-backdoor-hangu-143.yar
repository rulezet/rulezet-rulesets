import "pe"
rule _Virus_Hijack_Backdoor_Hangup_B_59_1_Virus_Hijack_Backdoor_Hangu_143 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Backdoor.Hangup.B_59_1.vir, Virus.Hijack_Backdoor.Hangup.B_6_1.vir, Virus.Infector_Gen.Heur.Mint.SP.Sneaky.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61ac79cb7e70dd73670785663963f5fd5fd5225c33f5d3a2f10b61575e2a34af"
    hash2       = "aa2ec179e68f43b116c3112baddb73d7dfc5971ca7686ad8a154c0da00ae9694"
    hash3       = "005e9b3733b327f5b4aa58d22ca13372e3f58de2f81a4015bc6b3889a82a98f6"

  strings:
    $s1 = "r %s sind keine Hilfeinformationen vorhanden.(Keine kontextsensitive Hilfe installiert.Es ist keine themenbasierte Hilfe install" wide
    $s2 = "ltiger Bilderlistenindex;ImageList-Daten konnten nicht aus dem Stream gelesen werden>ImageList-Daten konnten nicht in den Stream" wide
    $s3 = "tekontexts(Fehler beim Erzeugen einer FensterklasseEDeaktiviertes oder unsichtbares Fenster kann den Fokus nicht erhalten,Elemen" wide
    $s4 = "tzten Ressourcen-Stream kann nicht geschrieben werdenQCheckSynchronize wurde vom Thread $%x aufgerufen, der NICHT der Haupt-Thre" wide
    $s5 = "Kagee [Master]" fullword ascii
    $s6 = "Kagee [Slave]" fullword ascii
    $s7 = "EEigenschaft Visible kann in OnShow oder OnHide nicht ver" fullword wide
    $s8 = "elementesLFormular kann nicht erstellt werden. Zur Zeit sind keine MDI-Formulare aktiv6Steuerelement kann nicht sich selbst als " wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "bb74452d79a36382eece6690dc4983db" and (all of them)
    ) or (all of them)
}