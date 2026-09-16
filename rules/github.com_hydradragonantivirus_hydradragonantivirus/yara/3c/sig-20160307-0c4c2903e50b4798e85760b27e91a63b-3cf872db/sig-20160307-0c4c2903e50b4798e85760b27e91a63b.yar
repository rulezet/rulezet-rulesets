rule sig_20160307_0c4c2903e50b4798e85760b27e91a63b {
  meta:
    description = "datamaliciousorder - file 20160307_0c4c2903e50b4798e85760b27e91a63b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dddfad590c98533602da3ffe7d636e9d9e7b908ef594a7cc5dd88c54d6a842f6"

  strings:
    $s1  = "var By = true  , cmQs = BlC[7] + BlC[9] + BlC[11];" fullword ascii
    $s2  = "return bKrrpIh[0] + bKrrpIh[2] + bKrrpIh[4] + \".F\" + bKrrpIh[7] + bKrrpIh[9] + bKrrpIh[12] + bKrrpIh[14];" fullword ascii
    $s3  = "var BlC = (\"2.XMLHTTP GkLWbWJ skPYY XML ream St AEUvRUos AD gElybTW O RFxo D\").split(\" \");" fullword ascii
    $s4  = "var bKrrpIh = \"Sc WuEqPmT r IoRwejZjq ipting ACXwSXp EER ile oVYWKNdBcnzdpI System gv esQLp Obj PWUCEd ect HMKLITi\".split(\" " ascii
    $s5  = "YpkKs.open(rEJLp,lHxZx,false);" fullword ascii
    $s6  = "return BUQC.responseBody;" fullword ascii
    $s7  = "return new ActiveXObject(UqkXkl);" fullword ascii
    $s8  = "function iNxHs(UqkXkl) {" fullword ascii
    $s9  = "if (nEdut > 169029-952){return true;} else {return false;}" fullword ascii
    $s10 = "return fCHzP;" fullword ascii
    $s11 = "return mQ.ExpandEnvironmentStrings(NdUgJ[6]+NdUgJ[7]+NdUgJ[8]);" fullword ascii
    $s12 = "if (ldxMd == 971-771){return true;} else {return false;}" fullword ascii
    $s13 = "return TKOVUfT" fullword ascii
    $s14 = "return OBr.size;" fullword ascii
    $s15 = "function rXKs(nEdut) {" fullword ascii
    $s16 = "function gBzs(mjKuq) {" fullword ascii
    $s17 = "if(C>=b.length) {break;}" fullword ascii
    $s18 = "function eLww(NYRcr) {" fullword ascii
    $s19 = "function sKLw(TSFVU,OnpXq) {" fullword ascii
    $s20 = "function MgNF(YpkKs,lHxZx,rEJLp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}