rule sig_20150906_5b517f7c1bb638b37cbb426ef0261017 {
  meta:
    description = "datamaliciousorder - file 20150906_5b517f7c1bb638b37cbb426ef0261017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a08f87c8331bd87dbb3a5f2af5e14498d2d91c3e3edfa2951a0d94806be7ee"

  strings:
    $s1  = "var str=\"5557515E0D0A020B24060108130B0B000A1D4A070B09\";function amr438126() { return 'o.re'; }; /* var wvhr=amr199748(); */ fu" ascii
    $s2  = "() { return 'Shel'; }; /* var wvhr=amr190509(); */ function amr106860() { return '.com\"'; }; /* var wvhr=amr507953(); */ functi" ascii
    $s3  = "=amr389096(); */ function amr648284() { return 'tch '; }; function amr630474() { return '.Run'; }; /* var wvhr=amr648809(); */ /" ascii
    $s4  = "* var wvhr=amr274147(); */ function amr544986() { return '.R'; }; function amr537862() { return 'wri'; }; /* var wvhr=amr891636(" ascii
    $s5  = "hr=amr289738(); */ function amr658970() { return ' {}'; }; function amr245778() { return 'TEMP'; }; function amr277836() { retur" ascii
    $s6  = " 'ET\",'; }; /* var wvhr=amr685214(); */ /* var wvhr=amr557159(); */ function amr395382() { return '.onr'; }; function amr637598" ascii
    $s7  = "r wvhr=amr399302(); */ /* var wvhr=amr847686(); */ /* var wvhr=amr252666(); */ /* var wvhr=amr380175(); */ function amr844194() " ascii
    $s8  = "ion amr473746() { return '{ var'; }; /* var wvhr=amr359662(); */ /* var wvhr=amr760590(); */ function amr174538() { return 'Act'" ascii
    $s9  = "ction amr662532() { return '; }'; }; function amr651846() { return '(e'; }; /* var wvhr=amr112078(); */ /* var wvhr=amr144929();" ascii
    $s10 = "/* var wvhr=amr921763(); */ function amr124670() { return 'for '; }; /* var wvhr=amr125923(); */ /* var wvhr=amr402704(); */ /* " ascii
    $s11 = "mr522116(); */ function amr520052() { return 'a.'; }; function amr452374() { return '4 &'; }; /* var wvhr=amr684238(); */ /* var" ascii
    $s12 = "'); } '; }; /* var wvhr=amr830640(); */ /* var wvhr=amr618321(); */ function amr67678() { return 'ter'; }; function amr751582() " ascii
    $s13 = "mr619788() { return 'n,2)'; }; function amr584168() { return '1; xa'; }; function amr256464() { return 'ring.'; }; /* var wvhr=a" ascii
    $s14 = "2643(); */ function amr733772() { return 'umen'; }; /* var wvhr=amr501892(); */ /* var wvhr=amr893901(); */ /* var wvhr=amr36434" ascii
    $s15 = " function amr334828() { return '; var'; }; function amr748020() { return 'fr+'; }; function amr470184() { return '00) '; }; /* v" ascii
    $s16 = "n amr484432() { return 'ew Ac'; }; /* var wvhr=amr608803(); */ /* var wvhr=amr532783(); */ function amr263588() { return 'mC'; }" ascii
    $s17 = "ar wvhr=amr494129(); */ function amr840632() { return 'l(5'; }; /* var wvhr=amr534845(); */ function amr812136() { return 'ak'; " ascii
    $s18 = "var wvhr=amr917737(); */ function amr313456() { return 'xe'; }; /* var wvhr=amr961205(); */ function amr64116() { return 'mar'; " ascii
    $s19 = "turn '; }; '; }; function amr487994() { return 'tiveX'; }; /* var wvhr=amr413399(); */ /* var wvhr=amr558646(); */ function amr9" ascii
    $s20 = "'; }; function amr220844() { return 'Expa'; }; function amr242216() { return 's(\"%'; }; /* var wvhr=amr757609(); */ function am" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}