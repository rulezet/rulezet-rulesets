rule sig_20151022_8b61b8b64a9f5a2844f7a85f44f1f27b {
  meta:
    description = "datamaliciousorder - file 20151022_8b61b8b64a9f5a2844f7a85f44f1f27b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "749190e25222510e5c4998699fb561107c0e79a2d5b9ea206920c0bd31efd7e5"

  strings:
    $s1  = "var str=\"55515C5E0905160F01100D0A03240C161001070C070B0A03160117174A070B095E275E070D0A154A071E5E17555E5550505151575C5355505E55\"" ascii
    $s2  = " function qoi() { emtr += '{ va'; }; function hxfv() { emtr += ' } '; }; function zsgr() { emtr += 's.com'; }; function bns() { " ascii
    $s3  = "catch'; }; function wymm() { emtr += '.com '; }; function euvg() { emtr += '=3'; }; function ipa() { emtr += '.E'; }; function p" ascii
    $s4  = "= 'Run(f'; }; function hgol() { emtr += '.typ'; }; function oib() { emtr += '&& x'; }; function kvr() { emtr += '2.X'; }; functi" ascii
    $s5  = "jo() { emtr += 'o.res'; }; function hyci() { emtr += ' xo'; }; function ble() { emtr += 'i++) '; }; function vgw() { emtr += ');" ascii
    $s6  = "; }; function euae() { emtr += 'HTTP\"'; }; function kqgr() { emtr += ' 1; '; }; function xnl() { emtr += '); fo'; }; function c" ascii
    $s7  = "; function djje() { emtr += '.ope'; }; function dvs() { emtr += ' n<'; }; function qfnj() { emtr += '\")'; }; function rotq() { " ascii
    $s8  = "() { emtr += 'jand'; }; function wpl() { emtr += '1) '; }; function qxze() { emtr += 'tio'; }; function hjn() { emtr += ' i'; };" ascii
    $s9  = "function ooq() { emtr += 'adyS'; }; function mmao() { emtr += 'oupfo'; }; function yjgj() { emtr += 'ttp:/'; }; function docg() " ascii
    $s10 = "tr += 'ip'; }; function egxb() { emtr += 'i]'; }; function ruwf() { emtr += 'bre'; }; function vtlb() { emtr += 'xa.'; }; functi" ascii
    $s11 = "mtr += 'Body'; }; function ohpa() { emtr += 'b['; }; function tqhc() { emtr += 'ject'; }; function vxtz() { emtr += '; }'; }; fu" ascii
    $s12 = "+= ' }'; }; function suah() { emtr += 'tr'; }; function zajl() { emtr += 'B.St'; }; function adf() { emtr += '+) '; }; function " ascii
    $s13 = "emtr += 't.C'; }; function kmt() { emtr += 'romC'; }; function hha() { emtr += '+n, f'; }; function cpou() { emtr += 'pl'; }; fu" ascii
    $s14 = "; var zej = ''; function cbj() { emtr += 'ateOb'; }; function lmag() { emtr += 'po'; }; function sxgk() { emtr += 'ar w'; };bac(" ascii
    $s15 = "ction kpwj() { emtr += 'xe'; }; function oav() { emtr += ' dn ='; }; function ezik() { emtr += 'neros'; }; function uueq() { emt" ascii
    $s16 = "() { emtr += 're'; }; function xba() { emtr += 'o.'; }; function lwxw() { emtr += '5\"'; }; function heo() { emtr += 'n ='; }; f" ascii
    $s17 = "; }; function uck() { emtr += '(dn'; }; function evyu() { emtr += 'n+n+'; }; function wksk() { emtr += ' = 0;'; }; function ozow" ascii
    $s18 = " emtr += 'it(\" '; }; function yvnz() { emtr += '<b.'; }; function dsnl() { emtr += '); xa'; }; function dif() { emtr += 're'; }" ascii
    $s19 = "W'; }; function oqn() { emtr += ' try'; }; function ejg() { emtr += 'er/?i'; }; function nzo() { emtr += ' >'; }; function yits(" ascii
    $s20 = "n lery() { emtr += '200) '; }; function sswi() { emtr += '\".ex'; }; function etpl() { emtr += 'w.gr'; }; function des() { emtr " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}