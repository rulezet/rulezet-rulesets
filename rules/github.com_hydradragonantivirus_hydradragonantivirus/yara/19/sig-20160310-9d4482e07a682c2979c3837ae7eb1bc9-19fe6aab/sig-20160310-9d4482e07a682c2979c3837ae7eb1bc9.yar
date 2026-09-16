rule sig_20160310_9d4482e07a682c2979c3837ae7eb1bc9 {
  meta:
    description = "datamaliciousorder - file 20160310_9d4482e07a682c2979c3837ae7eb1bc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949b4da6a8eaa32f590ba1814dbb2e342776819f182321594080083ca3842a6b"

  strings:
    $s1  = "function FIiYcKw(IMAt,mSpYL) {" fullword ascii
    $s2  = "return IMAt.ExpandEnvironmentStrings(mSpYL);" fullword ascii
    $s3  = "var br = true  , zWUM = KWu[7] + KWu[9] + KWu[11];" fullword ascii
    $s4  = "return APjGKVD[0] + APjGKVD[2] + APjGKVD[4] + \".F\" + APjGKVD[7] + APjGKVD[9] + APjGKVD[12] + APjGKVD[14];" fullword ascii
    $s5  = "var APjGKVD = \"Sc kbVOvTR r fNkFUNFGa ipting BhTnKoz DZR ile DhTylOROxiBeuv System pT OIzqc Obj aNSYDm ect GsPrsug\".split(\" " ascii
    $s6  = "HMoAP.open(KSmRv,THsUs,false);" fullword ascii
    $s7  = "var KWu = (\"2.XMLHTTP fCXOofj YhbDu XML ream St XNEOHMPc AD ddkZYCY O EsUm D\").split(\" \");" fullword ascii
    $s8  = "function VovW(kIGzd,WubiM) {" fullword ascii
    $s9  = "Bkq = B; break; " fullword ascii
    $s10 = "function TLdC(IDRqd) {" fullword ascii
    $s11 = "function wjDn(pxzxs,ZbwmC) {" fullword ascii
    $s12 = "function SbNmTdSZ(XWK) {" fullword ascii
    $s13 = "if (ZtojG == 533-333){return true;} else {return false;}" fullword ascii
    $s14 = "function spPM(eEGRT) {" fullword ascii
    $s15 = "return FIiYcKw(vh,ttgpI[307-301]+ttgpI[126-119]+ttgpI[742-734]);" fullword ascii
    $s16 = "if (k >= KbGoS.length) {break;}" fullword ascii
    $s17 = "function kSvTA(JpLVlr) {" fullword ascii
    $s18 = "return hwuiff.position=773-773;" fullword ascii
    $s19 = "function pAHb(ANXmf) {" fullword ascii
    $s20 = "return XWK.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}