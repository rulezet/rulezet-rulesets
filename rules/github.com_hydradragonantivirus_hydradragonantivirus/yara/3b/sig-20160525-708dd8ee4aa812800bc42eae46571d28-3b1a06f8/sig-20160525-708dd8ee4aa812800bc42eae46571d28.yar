rule sig_20160525_708dd8ee4aa812800bc42eae46571d28 {
  meta:
    description = "datamaliciousorder - file 20160525_708dd8ee4aa812800bc42eae46571d28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfeec6f51699abb3fa1ee4592ecef6ad4a04094f1823e451e6573e539eb702e2"

  strings:
    $s1  = "(Math.cos(213), 2) - 1))-735)) aarEfBk += UEdXOvukrpdrdR(kCxBJgaMDuwqvirYOljdxF, yanjU);else aarEfBk += eteOSiKUXlP(kCxBJgaMDuwq" ascii
    $s2  = "function QkZSMtHE(dmbLzYyshVFFf) {var ALkvVfHfva = vCbAmHBplyoQZFoNuyB.join(bOXzMcwqPmwTcxS[0]);var kCxBJgaMDuwqvirYOljdxF, yanj" ascii
    $s3  = ")-146)) aarEfBk += mi(kCxBJgaMDuwqvirYOljdxF);else if (PopLDJDMseoSb == (799 + Math.round((Math.pow(Math.sin(213), 2) + Math.pow" ascii
    $s4  = "function lwgwibIeZaEQAIy(uFssHUFBevUNxA,hKyNFthZPIi){return uFssHUFBevUNxA.charAt(hKyNFthZPIi);}" fullword ascii
    $s5  = "function QkZSMtHE(dmbLzYyshVFFf) {var ALkvVfHfva = vCbAmHBplyoQZFoNuyB.join(bOXzMcwqPmwTcxS[0]);var kCxBJgaMDuwqvirYOljdxF, yanj" ascii
    $s6  = "virYOljdxF, yanjU, gVcVqkMQnf);} while (dkHYbTtiCjwLJG < dmbLzYyshVFFf.length);return aarEfBk;}" fullword ascii
    $s7  = "function eteOSiKUXlP(rhPct,XLsrH,eLdQdQVSbav){return String.fromCharCode(rhPct,XLsrH,eLdQdQVSbav);}" fullword ascii
    $s8  = "function UEdXOvukrpdrdR(dpvMRnMAxNbZxAddEq,uPmbkhkL){return String.fromCharCode(dpvMRnMAxNbZxAddEq,uPmbkhkL);}" fullword ascii
    $s9  = "function dmFjHcToRmhSn(qHvhmFFXGSf,wrHscDyrTPHmVUpNtAMBLZP){return qHvhmFFXGSf.indexOf(wrHscDyrTPHmVUpNtAMBLZP);}" fullword ascii
    $s10 = "function mi(jWbZXMSudmziSmiL){return String.fromCharCode(jWbZXMSudmziSmiL);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}