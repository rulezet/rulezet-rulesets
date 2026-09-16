rule sig_20160531_115ebc55bdf7a80e27cf5d706a3ecb38 {
  meta:
    description = "datamaliciousorder - file 20160531_115ebc55bdf7a80e27cf5d706a3ecb38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45c8690b81b76ac1ff8609da78c9b672c3940d6cd3df8d342651358dc67959d"

  strings:
    $s1  = "var IODTtapH=function(){return WScript.CreateObject(EzFKbkXuMaqPpGLxoOkfoVG[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function aIisJCxHmce(svRoCTnrbXgHi,iIOsVsNOHoDZlQyu){return svRoCTnrbXgHi.charAt(iIOsVsNOHoDZlQyu);}" fullword ascii
    $s3  = "function BfmqLyvrGNekdyceSAowcYE(ExPXOTDQLEgOAZvWSPvgwlG,aGdWDBrkTIftLKfJPlXoM){return String.fromCharCode(ExPXOTDQLEgOAZvWSPvgw" ascii
    $s4  = "(HPKJhpCjgH,0x1,0x0)}function rJDuUZFZhXU(lwYXNiiLdacqzg,vAIkzgvCrBAX,BlDAPAYegFOpIH){var MGgVyKyl=lwYXNiiLdacqzg.createtextfile" ascii
    $s5  = "function XmUftWnQLlCIsJpQBjqRJn(ODWHHYhbdWxodsQ,inRyigaPcPHldWmGfgZTCij){return ODWHHYhbdWxodsQ.indexOf(inRyigaPcPHldWmGfgZTCij)" ascii
    $s6  = "function MbwVtDio(){return lAyAbWPygxWXT(EzFKbkXuMaqPpGLxoOkfoVG[11],[2,4,8,10],EzFKbkXuMaqPpGLxoOkfoVG[12]);}" fullword ascii
    $s7  = "function lAyAbWPygxWXT(hQvTSorkNmfEkf,pSQOtHMtxah,LvCiATLgcH){bOEBUjcTebnJx=hQvTSorkNmfEkf.split(LvCiATLgcH);WPqKZNwgMeQx = EzFK" ascii
    $s8  = "function XmUftWnQLlCIsJpQBjqRJn(ODWHHYhbdWxodsQ,inRyigaPcPHldWmGfgZTCij){return ODWHHYhbdWxodsQ.indexOf(inRyigaPcPHldWmGfgZTCij)" ascii
    $s9  = "function AUNyNDLrdLhiAYRthtjKeX(PwIoszqTYGWq,KbbKMWjnQqnrbhVNGTRMApK,CUPLycBtOnxpFfGgZbSsG){return String.fromCharCode(PwIoszqTY" ascii
    $s10 = "function xbobkx(eMkoiWeucIHZe) {var OUsdImpd = fKgubRrWKGPYPTNSCQDDWs.join(EzFKbkXuMaqPpGLxoOkfoVG[7]);var KJGwqlFqJ, SMLjBLJcqe" ascii
    $s11 = "function AUNyNDLrdLhiAYRthtjKeX(PwIoszqTYGWq,KbbKMWjnQqnrbhVNGTRMApK,CUPLycBtOnxpFfGgZbSsG){return String.fromCharCode(PwIoszqTY" ascii
    $s12 = "yNDLrdLhiAYRthtjKeX(KJGwqlFqJ, SMLjBLJcqeMt, jhDazEYZvWB);} while (aqCCLEERhYGHH < eMkoiWeucIHZe.length);return GmTBmtscPgjcRe;}" ascii
    $s13 = "function mcuzUauipYB(){return lAyAbWPygxWXT(EzFKbkXuMaqPpGLxoOkfoVG[13],[0,3,6],EzFKbkXuMaqPpGLxoOkfoVG[14]);}" fullword ascii
    $s14 = "function ZozKtQfyiYHBeX(){return IODTtapH.ExpandEnvironmentStrings(DBnVtMEDWP())}" fullword ascii
    $s15 = "function xbobkx(eMkoiWeucIHZe) {var OUsdImpd = fKgubRrWKGPYPTNSCQDDWs.join(EzFKbkXuMaqPpGLxoOkfoVG[7]);var KJGwqlFqJ, SMLjBLJcqe" ascii
    $s16 = "GwqlFqJ);else if (gsnFffXzH == 64) GmTBmtscPgjcRe += BfmqLyvrGNekdyceSAowcYE(KJGwqlFqJ, SMLjBLJcqeMt);else GmTBmtscPgjcRe += AUN" ascii
    $s17 = "function whepndzIriyN(LLFOHSGmnFrV,HPKJhpCjgH) {var TrASyLSHpUvF=[EzFKbkXuMaqPpGLxoOkfoVG[15]];LLFOHSGmnFrV[TrASyLSHpUvF[0]]" fullword ascii
    $s18 = "function F(APgoqgpxeicjCcrDddNvFk){return String.fromCharCode(APgoqgpxeicjCcrDddNvFk);}" fullword ascii
    $s19 = "(vAIkzgvCrBAX,true);MGgVyKyl.WriteLine(BlDAPAYegFOpIH);MGgVyKyl.Close();}" fullword ascii
    $s20 = "(HPKJhpCjgH,0x1,0x0)}function rJDuUZFZhXU(lwYXNiiLdacqzg,vAIkzgvCrBAX,BlDAPAYegFOpIH){var MGgVyKyl=lwYXNiiLdacqzg.createtextfile" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}