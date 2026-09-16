rule sig_20160526_d60e92f4f665a2306b4db3bac2bd02a4 {
  meta:
    description = "datamaliciousorder - file 20160526_d60e92f4f665a2306b4db3bac2bd02a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b12576beec2c4b20adcce587ef4b1e45a66be2df81bf424842d7ac042eda1116"

  strings:
    $s1  = "function EOckdpfwSlXGE(hniUxNRzDWUeU) {var pxkaQrhqAezF = SYFYisc.join(gExwzNq[0]);var zQGztpbGySEuAS, VwCnznJDxPzFawAKUUXtWPZL," ascii
    $s2  = "GE(zQGztpbGySEuAS);else if (wbsXqsoARkOFvGCfkiEtC == (580 + Math.round((Math.pow(Math.sin(353), 2) + Math.pow(Math.cos(353), 2) " ascii
    $s3  = "function wvPXaWkOkdGHuNP(ZujQlBQJLg,NcfeHUNeWUUNSkJCdwYmy){return ZujQlBQJLg.charAt(NcfeHUNeWUUNSkJCdwYmy);}" fullword ascii
    $s4  = "- 1))-516)) lARAOmBE += XuNReFpPwkPavknshNTsOF(zQGztpbGySEuAS, VwCnznJDxPzFawAKUUXtWPZL);else lARAOmBE += GvjNJxVExXpQwfpXub(zQG" ascii
    $s5  = "function GvjNJxVExXpQwfpXub(IBxNZISRZiEPnfujras,XqjJkgAIcOMCHSIlxr,IcrQwlhYEmLbsdTEiGclOKk){return String.fromCharCode(IBxNZISRZ" ascii
    $s6  = "function GvjNJxVExXpQwfpXub(IBxNZISRZiEPnfujras,XqjJkgAIcOMCHSIlxr,IcrQwlhYEmLbsdTEiGclOKk){return String.fromCharCode(IBxNZISRZ" ascii
    $s7  = "function EOckdpfwSlXGE(hniUxNRzDWUeU) {var pxkaQrhqAezF = SYFYisc.join(gExwzNq[0]);var zQGztpbGySEuAS, VwCnznJDxPzFawAKUUXtWPZL," ascii
    $s8  = "ztpbGySEuAS, VwCnznJDxPzFawAKUUXtWPZL, QvlbOdmV);} while (BfvnVfAMw < hniUxNRzDWUeU.length);return lARAOmBE;}" fullword ascii
    $s9  = "function XvdhgNBitu(oclxSxYOWJ,NdzeMYctBp){return oclxSxYOWJ.indexOf(NdzeMYctBp);}" fullword ascii
    $s10 = "function XuNReFpPwkPavknshNTsOF(EOaNwszPFD,MtlwvcFEZRKbjSloyrIgh){return String.fromCharCode(EOaNwszPFD,MtlwvcFEZRKbjSloyrIgh);}" ascii
    $s11 = "function GE(gXuIfjfIMJCWDQRQoWok){return String.fromCharCode(gXuIfjfIMJCWDQRQoWok);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}