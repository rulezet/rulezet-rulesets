rule sig_20150905_c2c01ba462c9c5962edcfe3f02fc821e {
  meta:
    description = "datamaliciousorder - file 20150905_c2c01ba462c9c5962edcfe3f02fc821e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb8fefafe8aa49c0a81ba9b54d0754c68226c037476c76d0079a41f5a32798ed"

  strings:
    $s1  = "var str=\"5557515E0905160F01100D0A03240C160A0111160B14014A070B09\";function uu181662() { return 'var '; }; /* var yxd=uu765108()" ascii
    $s2  = "ar yxd=uu188965(); */ /* var yxd=uu725630(); */ /* var yxd=uu600662(); */ function uu67678() { return '.com '; }; /* var yxd=uu1" ascii
    $s3  = "u862382(); */ function uu299208() { return '.exe\"'; }; /* var yxd=uu798807(); */ /* var yxd=uu303556(); */ /* var yxd=uu109828(" ascii
    $s4  = "eturn '(\"GET'; }; function uu103298() { return '\")'; }; /* var yxd=uu171754(); */ function uu726648() { return '+\"'; }; /* va" ascii
    $s5  = "* var yxd=uu505312(); */ function uu92612() { return 'it\".s'; }; function uu160290() { return 'jec'; }; function uu391820() { r" ascii
    $s6  = "8() { return 'http'; }; /* var yxd=uu592992(); */ /* var yxd=uu805376(); */ /* var yxd=uu136789(); */ /* var yxd=uu181643(); */ " ascii
    $s7  = "eturn 'i<b.l'; }; /* var yxd=uu949979(); */ function uu356200() { return '2.XML'; }; function uu366886() { return '\");'; }; fun" ascii
    $s8  = ") { return 'a.siz'; }; function uu185224() { return 'fn'; }; /* var yxd=uu636983(); */ function uu527176() { return '.wr'; }; /*" ascii
    $s9  = "n'; }; function uu431002() { return ' && x'; }; function uu74802() { return 'ter'; }; /* var yxd=uu983499(); */ function uu32058" ascii
    $s10 = "; '; }; function uu829946() { return '(3'; }; function uu317018() { return ' var'; }; /* var yxd=uu603157(); */ /* var yxd=uu684" ascii
    $s11 = "6() { return 'tate'; }; function uu598416() { return 'aveTo'; }; /* var yxd=uu336820(); */ /* var yxd=uu429768(); */ /* var yxd=" ascii
    $s12 = "ion uu616226() { return ' ws.'; }; function uu580606() { return 'osit'; }; /* var yxd=uu676566(); */ function uu630474() { retur" ascii
    $s13 = "696() { return 'at'; }; function uu49868() { return 'om id'; }; /* var yxd=uu507945(); */ /* var yxd=uu513701(); */ /* var yxd=u" ascii
    $s14 = "n uu227968() { return 'Stri'; }; /* var yxd=uu775468(); */ function uu776516() { return '(er'; }; function uu459498() { return '" ascii
    $s15 = "=uu715362(); */ function uu188786() { return ' = w'; }; /* var yxd=uu705107(); */ /* var yxd=uu568116(); */ /* var yxd=uu382958(" ascii
    $s16 = "); */ function uu32058() { return 'elmar'; }; /* var yxd=uu671588(); */ /* var yxd=uu418585(); */ /* var yxd=uu962889(); */ /* v" ascii
    $s17 = "on uu609102() { return '; t'; }; function uu544986() { return '); i'; }; /* var yxd=uu543041(); */ /* var yxd=uu492253(); */ fun" ascii
    $s18 = "0() { return ' xo ='; }; /* var yxd=uu372165(); */ /* var yxd=uu536634(); */ function uu295646() { return ')+\"'; }; function uu" ascii
    $s19 = "tion uu206596() { return 'en'; }; /* var yxd=uu484056(); */ function uu694590() { return '://\"'; }; function uu758706() { retur" ascii
    $s20 = "3(); */ function uu370448() { return ' xo'; }; /* var yxd=uu649203(); */ /* var yxd=uu332904(); */ function uu520052() { return " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}