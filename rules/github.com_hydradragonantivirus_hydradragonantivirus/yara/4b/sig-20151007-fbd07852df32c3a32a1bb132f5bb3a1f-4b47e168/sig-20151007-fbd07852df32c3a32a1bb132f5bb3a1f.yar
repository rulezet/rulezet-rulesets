rule sig_20151007_fbd07852df32c3a32a1bb132f5bb3a1f {
  meta:
    description = "datamaliciousorder - file 20151007_fbd07852df32c3a32a1bb132f5bb3a1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58013aa7e580fbd075017c2f4fb7eae14d12d5123185c5ae65f8d631da91451f"

  strings:
    $s1  = "b() { mvn += '?r'; }; function qxpi() { mvn += '&id'; }; function ntjl() { mvn += '.com '; }; function ejgl() { mvn += 'k;'; }; " ascii
    $s2  = "var str=\"5551565E060B0300050A240C160A0111160B14014A070B095E225E110A0D0F09011005084A16115E17011614565E55505050555D51535D565E55\"" ascii
    $s3  = " }; function vgd() { mvn += '.wri'; }; function aon() { mvn += '.exe\"'; }; function hwaa() { mvn += 'ze'; }; function wmr() { m" ascii
    $s4  = ".'; }; function esys() { mvn += 'ch'; }; function gofe() { mvn += '.php'; }; function wxi() { mvn += 'po'; }; function ihl() { m" ascii
    $s5  = " }; var reov = ''; function dlw() { mvn += 'try'; }; function orbw() { mvn += '()*'; }; function pjrk() { mvn += '.Res'; }; func" ascii
    $s6  = "ya'; }; function lob() { mvn += ' && x'; }; function frcz() { mvn += ' { '; }; function jnur() { mvn += '222);'; }; function xae" ascii
    $s7  = "function bpcx() { mvn += 'ak'; }; function buz() { mvn += 'ptF'; }; function nhim() { mvn += '; va'; }; function yamg() { reov +" ascii
    $s8  = ") { mvn += 'HTT'; }; function ekz() { mvn += 'dyst'; }; function dbw() { mvn += 'vid'; }; function cryo() { mvn += 'f (d'; }; fu" ascii
    $s9  = "on ouq() { mvn += '= '; }; function qiz() { mvn += 'ToF'; }; function xotp() { mvn += ' 500'; }; function lyo() { mvn += '10000'" ascii
    $s10 = " '(\"AD'; }; function winq() { mvn += '\"+M'; }; function exe() { mvn += ' } c'; }; function ryp() { mvn += ', fa'; }; function " ascii
    $s11 = " += 'ar w'; }; function jfz() { mvn += 'ull'; }; function vzmu() { mvn += 'Scri'; }; function bqxa() { mvn += '); dl'; }; functi" ascii
    $s12 = "= 'val'; };  function omi() { mvn += 'stat'; }; function ocds() { mvn += 'csch'; }; function fnp() { mvn += '(fr)'; }; function " ascii
    $s13 = ") { mvn += 'nd();'; }; function sqff() { mvn += '.ty'; }; var srh = ''; function jww() { mvn += 's = '; }; function cpf() { mvn " ascii
    $s14 = "iog(); auz(); rel(); nock(); hog(); wmr(); dua(); vjg(); ngv(); jin(); kvd(); cnht(); xpa(); jzkv(); fdd(); hgjw(); sqff(); bbu(" ascii
    $s15 = " }; function tnvm() { mvn += ' == 4'; }; function ydj() { srh(mvn); };  function rtp() { mvn += 'onr'; }; function qqw() { mvn +" ascii
    $s16 = " }; function gvty() { mvn += 'e('; }; function kzvh() { mvn += 'e);'; }; function cnht() { mvn += 'tream'; }; function snit() { " ascii
    $s17 = " += '\".s'; }; function bym() { mvn += 'pons'; }; function ebeh() { mvn += ' w'; }; function moty() { mvn += '); '; }; function " ascii
    $s18 = "nction yjxh() { mvn += ') {'; }; function hgjw() { mvn += '); xa'; }; function ejh() { mvn += 've'; }; function vkf() { mvn += '" ascii
    $s19 = " }; function itba() { mvn += 'rea'; }; function uqym() { mvn += 'th; '; }; function uhpq() { mvn += 'WS'; }; function ggpv() { m" ascii
    $s20 = "v'; }; var mvn = '';sfyz(); wedk(); ycxh(); fnp(); nqrn(); liaa(); ouq(); wast(); jren(); aqd(); hwaa(); oai(); bpcx(); ntjl(); " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}