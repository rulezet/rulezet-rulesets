rule sig_20160526_4c4c36233de9f44d5e5004d70a0159d3 {
  meta:
    description = "datamaliciousorder - file 20160526_4c4c36233de9f44d5e5004d70a0159d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e3cc4e37485d78a1304499493b5329355d8647eb04d8d4c776b28354f6bf80"

  strings:
    $s1  = "ath.cos(790), 2) - 1))-824)) VQxkftGhSY += hH(jbOccFMhZLTXJMHhfFOhIUs);else if (COKOf == (361 + Math.round((Math.pow(Math.sin(99" ascii
    $s2  = "3), 2) + Math.pow(Math.cos(993), 2) - 1))-297)) VQxkftGhSY += WWyyN(jbOccFMhZLTXJMHhfFOhIUs, KETLuXwoMKdxWK);else VQxkftGhSY += " ascii
    $s3  = "function ZoJXSebPUg(HwGEOlPPwFrkc) {var yoeOJXwgmZUKTkfr = ZebICpLIcQNmFt.join(PvpGduPFIDg[0]);var jbOccFMhZLTXJMHhfFOhIUs, KETL" ascii
    $s4  = "function awAJOgEJoKzb(ziUjkMGLeIlpZT,ETcAZPZYgsUZ){return ziUjkMGLeIlpZT.charAt(ETcAZPZYgsUZ);}" fullword ascii
    $s5  = "th);return VQxkftGhSY;}" fullword ascii
    $s6  = "function rdGBEdNcGxuAzmhrxoC(siBeYNfZ,OwxlLiDLQUozOwwu,dBLRwkbr){return String.fromCharCode(siBeYNfZ,OwxlLiDLQUozOwwu,dBLRwkbr);" ascii
    $s7  = "rdGBEdNcGxuAzmhrxoC(jbOccFMhZLTXJMHhfFOhIUs, KETLuXwoMKdxWK, nGOZNxmqrJOfcBgtVXqTluP);} while (oipVgLNDgRNZ < HwGEOlPPwFrkc.leng" ascii
    $s8  = "function ZoJXSebPUg(HwGEOlPPwFrkc) {var yoeOJXwgmZUKTkfr = ZebICpLIcQNmFt.join(PvpGduPFIDg[0]);var jbOccFMhZLTXJMHhfFOhIUs, KETL" ascii
    $s9  = "function WWyyN(eByxVHOkLXhSWKVqXd,ZtJWqrmVEjphRmRq){return String.fromCharCode(eByxVHOkLXhSWKVqXd,ZtJWqrmVEjphRmRq);}" fullword ascii
    $s10 = "function rdGBEdNcGxuAzmhrxoC(siBeYNfZ,OwxlLiDLQUozOwwu,dBLRwkbr){return String.fromCharCode(siBeYNfZ,OwxlLiDLQUozOwwu,dBLRwkbr);" ascii
    $s11 = "function hH(YBvAEppfJ){return String.fromCharCode(YBvAEppfJ);}" fullword ascii
    $s12 = "function aJPNKXwqMwMlRbr(kjBVeyYeNxax,unxxtcHSeHwKAZ){return kjBVeyYeNxax.indexOf(unxxtcHSeHwKAZ);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}