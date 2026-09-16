rule sig_20160526_1ff1b342f6a6b9389303f7f90f8a226c {
  meta:
    description = "datamaliciousorder - file 20160526_1ff1b342f6a6b9389303f7f90f8a226c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdddd4d800286453b38f332885b1cc9588f18b91cb15669cb9657e6be29f95d2"

  strings:
    $s1  = "nd((Math.pow(Math.sin(552), 2) + Math.pow(Math.cos(552), 2) - 1))-373)) cCUyaeHoeqZxwCLV += J(tFTlsTgOBEkHUtNJxQBCAZNS);else if " ascii
    $s2  = "function VtOERg(DYzHmWuxYjBJK) {var jHCaMTgoDhbIQDvAJkUBssjs = yBhlmxvkUzTbeymbG.join(EZausglRVPOPB[0]);var tFTlsTgOBEkHUtNJxQBC" ascii
    $s3  = "function ZjVcUaYcg(NxcPmKZJVzKDcfngRu,dtCARaYiQXdTaSAMVgO){return NxcPmKZJVzKDcfngRu.charAt(dtCARaYiQXdTaSAMVgO);}" fullword ascii
    $s4  = "function vHAUskMKpfGauhfvPrOjBu(vyoeiZSmVS,GJTMyxoZikCbnllAcSI){return vyoeiZSmVS.indexOf(GJTMyxoZikCbnllAcSI);}" fullword ascii
    $s5  = "function QwAMpBgQriU(jSCcVtcNLmUBFE,rUuxgmanoqifeku){return String.fromCharCode(jSCcVtcNLmUBFE,rUuxgmanoqifeku);}" fullword ascii
    $s6  = "function J(muqDrzcJDgwScgMkN){return String.fromCharCode(muqDrzcJDgwScgMkN);}" fullword ascii
    $s7  = "function xCFtHJn(WVPkBELvYpNCWDzSWrU,FpxZyveOUInFAo,qYBNHPSYJFxWIgVBSqja){return String.fromCharCode(WVPkBELvYpNCWDzSWrU,FpxZyve" ascii
    $s8  = "function xCFtHJn(WVPkBELvYpNCWDzSWrU,FpxZyveOUInFAo,qYBNHPSYJFxWIgVBSqja){return String.fromCharCode(WVPkBELvYpNCWDzSWrU,FpxZyve" ascii
    $s9  = "bGqlRTAAbGDVfsJ, QZlhZkiBtJqANZSGqZyw);} while (zbIKtdiRAqUukY < DYzHmWuxYjBJK.length);return cCUyaeHoeqZxwCLV;}" fullword ascii
    $s10 = "function VtOERg(DYzHmWuxYjBJK) {var jHCaMTgoDhbIQDvAJkUBssjs = yBhlmxvkUzTbeymbG.join(EZausglRVPOPB[0]);var tFTlsTgOBEkHUtNJxQBC" ascii
    $s11 = "QwAMpBgQriU(tFTlsTgOBEkHUtNJxQBCAZNS, kXgXNudbGqlRTAAbGDVfsJ);else cCUyaeHoeqZxwCLV += xCFtHJn(tFTlsTgOBEkHUtNJxQBCAZNS, kXgXNud" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}