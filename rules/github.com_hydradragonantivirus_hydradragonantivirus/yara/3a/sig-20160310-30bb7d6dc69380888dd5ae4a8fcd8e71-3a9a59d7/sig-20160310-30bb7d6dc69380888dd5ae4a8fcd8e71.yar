rule sig_20160310_30bb7d6dc69380888dd5ae4a8fcd8e71 {
  meta:
    description = "datamaliciousorder - file 20160310_30bb7d6dc69380888dd5ae4a8fcd8e71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e816d4c8e5f50bf6dec61faecec634db35e891e722f943e02a4583d278ff7fe2"

  strings:
    $s1  = "return mODJZoT[0] + mODJZoT[2] + mODJZoT[4] + \".F\" + mODJZoT[7] + mODJZoT[9] + mODJZoT[12] + mODJZoT[14];" fullword ascii
    $s2  = "var PL = true  , Koze = pAU[7] + pAU[9] + pAU[11];" fullword ascii
    $s3  = "var mODJZoT = \"Sc WyqJyfY r tAAJXlhEQ ipting vpBcOKl qgL ile IweGUKlmLmSLFa System yf ykBJm Obj PMpqpt ect LEbmTVd\".split(\" " ascii
    $s4  = "var pAU = (\"2.XMLHTTP cFTaPgJ eSFTd XML ream St mRLsjwtq AD dkJWEIT O Lgxr D\").split(\" \");" fullword ascii
    $s5  = "bMJxz.open(NZujK,nYcTV,false);" fullword ascii
    $s6  = "function PXGQ(bnXiK) {" fullword ascii
    $s7  = "function tvKA(LLQTc,IpUGb) {" fullword ascii
    $s8  = "function OmYtbgg(EyxN,ZARdM) {" fullword ascii
    $s9  = "return fnCz.responseBody;" fullword ascii
    $s10 = "function sNjf(npjqK) {" fullword ascii
    $s11 = "function ECYVADWKg(lxQvA,kLfqH,qvamJ,KVwm) {" fullword ascii
    $s12 = "if(r>=v.length) {break;}" fullword ascii
    $s13 = "function wlvl(OwySb) {" fullword ascii
    $s14 = "function DZFlTXwa(hVo) {" fullword ascii
    $s15 = "function coArAar(fnCz) {" fullword ascii
    $s16 = "if (K >= OwySb.length) {break;}" fullword ascii
    $s17 = "return mCWDExI" fullword ascii
    $s18 = "function tdWn(VBRvN) {" fullword ascii
    $s19 = "function DkNR(KyMGY) {" fullword ascii
    $s20 = "qTA = r; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}