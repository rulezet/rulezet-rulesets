rule sig_20150930_1035692ace28d3cbaa318a95f2e6120d {
  meta:
    description = "datamaliciousorder - file 20150930_1035692ace28d3cbaa318a95f2e6120d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adf8426df388a15f47f2a6b1ffac0446d0a025442adf130584d366232ecdc4e3"

  strings:
    $s1  = "var str=\"55505D5E060B0300050A240C160A0111160B14014A070B095E225E0611000301100C0B09010D0A171116050A07014A0D0A020B5E17011614565E55" ascii
    $s2  = "function kjibmpt() { fyii += '.com'; }; function nypb() { fyii += 'xa.t'; }; function tagogc() { fyii += 'i+'; }; function kkmmg" ascii
    $s3  = "+= 'ad'; }; function oyyieem() { fyii += 'ript.'; }; function dllnw() { fyii += 'hp?r'; }; function gwdpkbg() { fyii += 'n(fn'; " ascii
    $s4  = "}; function zfoy() { fyii += ')*'; }; function femrh() { fyii += 'GET\",'; }; function ldsjf() { fyii += 'Act'; }; function ujum" ascii
    $s5  = " { fyii += 'pen(\"'; }; function jlvripc() { fyii += 'vi'; }; function tdsahjk() { fyii += ' && '; }; function pelt() { fyii += " ascii
    $s6  = "+= '.sen'; }; function hxgy() { fyii += ' 200'; }; function orvdz() { fyii += '{ ws.'; }; function jwbk() { fyii += 'media'; }; " ascii
    $s7  = "cxvn() { fyii += 'exe'; }; function zpvbzbs() { fyii += '\" '; }; function iqbnqn() { fyii += '.Str'; }; function lzlan() { fyii" ascii
    $s8  = "; }; function dcxs() { fyii += '(xo.'; }; function qyas() { fyii += 'g.fro'; }; function wcbpy() { fyii += 'arCod'; }; function " ascii
    $s9  = " }; function wbip() { fyii += '00'; }; function uxqmtn() { fyii += '.o'; }; function vcrmu() { fyii += 'tion('; }; function aqvr" ascii
    $s10 = "function fftdcm() { fyii += 'Ru'; }; function ipjdhsm() { fyii += 'r) {'; }; function wmmma() { fyii += '(); '; }; function xoxn" ascii
    $s11 = "05057525256545250\";function zlitf() { fyii += 'MLHTT'; }; function cnfo() { fyii += '+) '; }; function gpcyhlb() { fyii += '\"." ascii
    $s12 = "ySt'; }; function lmlnnw() { fyii += 'ch ('; }; function xxtv() { fyii += 'try '; }; function imtxr() { fyii += 'nd='; }; functi" ascii
    $s13 = " 'r, fa'; }; function txcb() { fyii += 'andE'; }; function doprhfn() { fyii += ') { '; }; function accuj() { fyii += '592)'; }; " ascii
    $s14 = "{ fyii += '; x'; }; function qmin() { fyii += 'funct'; }; function tyqi() { fyii += 'r i'; }; function ygitpz() { fyii += ') { '" ascii
    $s15 = "ion xkoeud() { fyii += '; } c'; }; function ghypam() { fyii += ';'; }; function sibefgk() { fyii += 'ze'; }; function laek() { f" ascii
    $s16 = " }; function slir() { fyii += ' i-f'; }; function jzke() { fyii += 'ys'; }; function fxkzx() { fyii += 'io'; }; function uyvqfeg" ascii
    $s17 = "function njkujp() { fyii += 'er) {'; }; function uatdfrp() { fyii += 'w Act'; }; function lujjizm() { fyii += '100'; }; function" ascii
    $s18 = "yii += 'men'; }; function urvpju() { fyii += 'e);'; }; function pjln() { fyii += 'iveX'; }; function lldy() { fyii += 'unc'; }; " ascii
    $s19 = "}; function karigyw() { fyii += ':/'; }; function grpb() { fyii += 'te'; }; function kxqsdw() { fyii += ' ne'; }; function gtutv" ascii
    $s20 = "; }; function evplppc() { fyii += 'ttp'; }; function mfoa() { fyii += 'tch'; }; function uffah() { fyii += 'EMP'; }; function lk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}