rule sig_20151022_5f0e560b8df2f628625f2680f28e6981 {
  meta:
    description = "datamaliciousorder - file 20151022_5f0e560b8df2f628625f2680f28e6981.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d92858a9248505c70d0559874e5c89ecdfd60959f7de2f6668326dccf9b1444e"

  strings:
    $s1  = "var str=\"55515C5E0905160F01100D0A03240C160A0111160B14014A070B095E275E05070701080116051001060D1E4A070B095E17555E5550505151575450" ascii
    $s2  = " += '.com '; }; function etu() { mui += 'for'; }; var geqq = ''; function dvpm() { mui += 'xe\"'; }; function vel() { mui += '; " ascii
    $s3  = "nction nbj() { mui += 'GET\"'; }; function flu() { mui += '.co'; }; function zamv() { mui += '.f'; }; function cns() { mui += 'n" ascii
    $s4  = "}; function awf() { mui += 'nte'; }; function qif() { mui += '.sen'; }; function fem() { mui += '(92)'; }; function tzdi() { mui" ascii
    $s5  = "c() { mui += 'warr'; }; function qfw() { mui += 'tch '; }; function bibz() { mui += '= '; }; function vnru() { mui += 'a.siz'; }" ascii
    $s6  = "; function gzt() { mui += '.Cre'; }; function qor() { mui += 'cou'; }; function axsv() { mui += ' v'; }; function kaaf() { mui +" ascii
    $s7  = "; };  function klsk() { mui += 'ng.f'; }; function gdt() { mui += '.XML'; }; function orp() { mui += '= WS'; }; function htd() {" ascii
    $s8  = "fn'; }; function hbfg() { mui += '73'; }; function liy() { mui += 'Fil'; }; function lsz() { mui += 'a '; }; function vlzb() { m" ascii
    $s9  = "il() { mui += 'tl'; }; function vjjx() { mui += 'k;'; }; function vqk() { mui += 'e >'; }; function ysqn() { mui += ' { '; }; fu" ascii
    $s10 = "nction kvi() { mui += 'reate'; }; function hev() { mui += '; br'; }; function idcs() { mui += '+\"/'; }; function svw() { mui +=" ascii
    $s11 = " }; function ccme() { mui += '+S'; }; function qiu() { mui += 'fpa'; }; function wpd() { mui += 'DOD'; }; function znw() { mui +" ascii
    $s12 = " function uue() { mui += 'tp://'; }; function zlm() { mui += 'om w'; }; function mzd() { mui += 'plit'; }; function yli() { mui " ascii
    $s13 = "; function loe() { mui += 'soc'; }; function hyf() { mui += ' 1;'; }; function atu() { mui += 'a.t'; }; function okkt() { mui +=" ascii
    $s14 = "rly() { mui += 'Obj'; }; function hbk() { mui += '; if '; }; function hnff() { mui += ' i'; }; function kdoi() { mui += '-as'; }" ascii
    $s15 = "; }; function zgyh() { mui += 'sta'; }; function kqqf() { mui += 'ro'; }; function abg() { mui += '; va'; }; function arbp() { m" ascii
    $s16 = "Exp'; }; function xbh() { mui += 'r/'; }; function gouc() { mui += '{ ld '; }; function emew() { mui += ' { d'; }; function uops" ascii
    $s17 = "}; function gzn() { mui += 'nama'; }; function wsjd() { mui += 'cript'; }; function mlmw() { mui += ' xo'; }; function aiqa() { " ascii
    $s18 = "ui += 'Scri'; }; function hntm() { mui += '=3; '; }; function qya() { mui += 'e(f'; }; function cyns() { cqk = geqq[rlfc]; };  f" ascii
    $s19 = "= '.Ru'; }; function icf() { mui += 'ar '; }; function opd() { mui += 'tu'; }; function rcr() { mui += '; var'; }; function iahz" ascii
    $s20 = "() { mui += '(); x'; }; function xdzy() { mui += ' (va'; }; function oqw() { mui += '+\"984'; }; function wmwt() { mui += '{ '; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}