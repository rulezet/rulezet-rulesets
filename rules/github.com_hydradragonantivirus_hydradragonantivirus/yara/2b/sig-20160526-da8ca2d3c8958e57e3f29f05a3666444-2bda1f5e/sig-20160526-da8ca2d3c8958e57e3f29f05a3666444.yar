rule sig_20160526_da8ca2d3c8958e57e3f29f05a3666444 {
  meta:
    description = "datamaliciousorder - file 20160526_da8ca2d3c8958e57e3f29f05a3666444.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "399a94ee32eba12efd3a59a1f7db1ae4a08f0a23cf52220add2d7fc03311f3e3"

  strings:
    $s1  = " QZ(YqSEzyA);else if (aYZTvoff == (1053 + Math.round((Math.pow(Math.sin(422), 2) + Math.pow(Math.cos(422), 2) - 1))-989)) aeCLdM" ascii
    $s2  = "function CmGRwP(INGyaboKaVRRw) {var MaqtzpgTsVtlfiBozycH = GZRsKPaBxfXQEQqZdhFqAnM.join(suLJczzQ[0]);var YqSEzyA, VThrdOQSCdBEjj" ascii
    $s3  = "function ZRbqteIOiFzXHRanzHk(wTAsmCOkcscZ,RcnxVY){return wTAsmCOkcscZ.charAt(RcnxVY);}" fullword ascii
    $s4  = "tngBBRZADvcrA += pjqAizjmr(YqSEzyA, VThrdOQSCdBEjj);else aeCLdMtngBBRZADvcrA += fZPGbYpBjelkG(YqSEzyA, VThrdOQSCdBEjj, Hpcoxaubi" ascii
    $s5  = "Cn);} while (mgxoCdyLId < INGyaboKaVRRw.length);return aeCLdMtngBBRZADvcrA;}" fullword ascii
    $s6  = "function pjqAizjmr(UyVMBBVYIUrnhDjefetBR,OxDaqGKvpDNXvoqzdCiGn){return String.fromCharCode(UyVMBBVYIUrnhDjefetBR,OxDaqGKvpDNXvoq" ascii
    $s7  = "function glIzwvFGHBkXeSSsjKw(nYnZdrkbVfrdvIMwOGqN,kZiyuwIDycRX){return nYnZdrkbVfrdvIMwOGqN.indexOf(kZiyuwIDycRX);}" fullword ascii
    $s8  = "function pjqAizjmr(UyVMBBVYIUrnhDjefetBR,OxDaqGKvpDNXvoqzdCiGn){return String.fromCharCode(UyVMBBVYIUrnhDjefetBR,OxDaqGKvpDNXvoq" ascii
    $s9  = "function fZPGbYpBjelkG(UEgiuQlLIlynuzWKbscU,kpkuMtOOxv,ZYGWeqGfMOa){return String.fromCharCode(UEgiuQlLIlynuzWKbscU,kpkuMtOOxv,Z" ascii
    $s10 = "function QZ(cbAAjUBVrlPlDGtJGenWKs){return String.fromCharCode(cbAAjUBVrlPlDGtJGenWKs);}" fullword ascii
    $s11 = "function CmGRwP(INGyaboKaVRRw) {var MaqtzpgTsVtlfiBozycH = GZRsKPaBxfXQEQqZdhFqAnM.join(suLJczzQ[0]);var YqSEzyA, VThrdOQSCdBEjj" ascii
    $s12 = "function fZPGbYpBjelkG(UEgiuQlLIlynuzWKbscU,kpkuMtOOxv,ZYGWeqGfMOa){return String.fromCharCode(UEgiuQlLIlynuzWKbscU,kpkuMtOOxv,Z" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}