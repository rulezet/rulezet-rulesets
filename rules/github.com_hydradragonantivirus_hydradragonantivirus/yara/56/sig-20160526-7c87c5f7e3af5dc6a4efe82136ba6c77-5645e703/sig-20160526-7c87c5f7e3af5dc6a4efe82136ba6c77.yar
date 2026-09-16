rule sig_20160526_7c87c5f7e3af5dc6a4efe82136ba6c77 {
  meta:
    description = "datamaliciousorder - file 20160526_7c87c5f7e3af5dc6a4efe82136ba6c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eaf098ee69566e8dd2a9806d39f0097891025652b815e1bf2fbdc5a211ddb8e"

  strings:
    $s1  = "function XbltVZfTXaaVc(OfQaXXZXAmuyD) {var CfqBYGXaYatssGjPkwVB = rRbLaXQKWXp.join(eOFxwWfzYTXdCjUGbdaLbw[0]);var hRlVxYgqd, qhq" ascii
    $s2  = "6 + Math.round((Math.pow(Math.sin(75), 2) + Math.pow(Math.cos(75), 2) - 1))-62)) ykZxWheIxqKmvOgYcoyZKc += A(hRlVxYgqd);else if " ascii
    $s3  = "function NZjtRpoMgVfvICKCFIGEr(ECpYKcWPQxgFDbYIvGgIV,wzDTYWtQYtjlk){return ECpYKcWPQxgFDbYIvGgIV.charAt(wzDTYWtQYtjlk);}" fullword ascii
    $s4  = "function XbltVZfTXaaVc(OfQaXXZXAmuyD) {var CfqBYGXaYatssGjPkwVB = rRbLaXQKWXp.join(eOFxwWfzYTXdCjUGbdaLbw[0]);var hRlVxYgqd, qhq" ascii
    $s5  = "function YyVjuVQvZprRCrWqFviWS(cGHxOrSLB,FzYNzvlWWMrMpaQtBnbrFqhX,aYLBKUSUZSqlbOtsSeNU){return String.fromCharCode(cGHxOrSLB,FzY" ascii
    $s6  = "function dXPaWBWrEOpvdzLtvTmamK(dQbSLPBJaSnSxoTvJ,Smoauf){return String.fromCharCode(dQbSLPBJaSnSxoTvJ,Smoauf);}" fullword ascii
    $s7  = "function pjeUWlxnnU(OzhSWbGWyNFtOakG,IryBRkcm){return OzhSWbGWyNFtOakG.indexOf(IryBRkcm);}" fullword ascii
    $s8  = "c += dXPaWBWrEOpvdzLtvTmamK(hRlVxYgqd, qhqKF);else ykZxWheIxqKmvOgYcoyZKc += YyVjuVQvZprRCrWqFviWS(hRlVxYgqd, qhqKF, MMxNaw);} w" ascii
    $s9  = "function A(JFVIAPDQsuppzi){return String.fromCharCode(JFVIAPDQsuppzi);}" fullword ascii
    $s10 = "function YyVjuVQvZprRCrWqFviWS(cGHxOrSLB,FzYNzvlWWMrMpaQtBnbrFqhX,aYLBKUSUZSqlbOtsSeNU){return String.fromCharCode(cGHxOrSLB,FzY" ascii
    $s11 = "hile (xlrBVQ < OfQaXXZXAmuyD.length);return ykZxWheIxqKmvOgYcoyZKc;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}