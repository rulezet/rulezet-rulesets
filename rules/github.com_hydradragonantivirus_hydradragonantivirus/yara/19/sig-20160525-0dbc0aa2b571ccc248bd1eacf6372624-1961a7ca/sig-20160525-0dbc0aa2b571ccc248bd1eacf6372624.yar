rule sig_20160525_0dbc0aa2b571ccc248bd1eacf6372624 {
  meta:
    description = "datamaliciousorder - file 20160525_0dbc0aa2b571ccc248bd1eacf6372624.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6245d5f20893389f4038d427e345ee7e5dc80c7385aaef596a3313face5cbe62"

  strings:
    $s1  = "Ksx += Xa(GwAbqskckBKRrrHv);else if (hdLqOZZTu == (668 + Math.round((Math.pow(Math.sin(46), 2) + Math.pow(Math.cos(46), 2) - 1))" ascii
    $s2  = "function OmAAuokiD(lPOqmutHqewHv) {var KgTUDztucbWwXKGkSmXVsylK = BfKiXBWDANCmsdhDWlMhb.join(GDrwP[0]);var GwAbqskckBKRrrHv, PEG" ascii
    $s3  = "function ipWpnYGLVYJQaqIH(NBMql,zCEMInZ){return NBMql.charAt(zCEMInZ);}" fullword ascii
    $s4  = "function wHuDaHWLCYN(CIQSkGlOReLiakIfYBRfrLE,WrVzUQibROSSLyE,uVSBRzTfq){return String.fromCharCode(CIQSkGlOReLiakIfYBRfrLE,WrVzU" ascii
    $s5  = "qsrbsy);} while (hybeaI < lPOqmutHqewHv.length);return xZFKsx;}" fullword ascii
    $s6  = "function VPymP(RCCEddcijWAl,xfuyoDGjmkSndtjpyMEh){return String.fromCharCode(RCCEddcijWAl,xfuyoDGjmkSndtjpyMEh);}" fullword ascii
    $s7  = "function KizytTyaxudYwcSJ(YFtzWbfhuREQsotEXdsrdIu,QtYWqZuErWQeMWzQXmO){return YFtzWbfhuREQsotEXdsrdIu.indexOf(QtYWqZuErWQeMWzQXm" ascii
    $s8  = "function Xa(wUJlNcQeeSIqyoLGhCps){return String.fromCharCode(wUJlNcQeeSIqyoLGhCps);}" fullword ascii
    $s9  = "function wHuDaHWLCYN(CIQSkGlOReLiakIfYBRfrLE,WrVzUQibROSSLyE,uVSBRzTfq){return String.fromCharCode(CIQSkGlOReLiakIfYBRfrLE,WrVzU" ascii
    $s10 = "-604)) xZFKsx += VPymP(GwAbqskckBKRrrHv, PEGxfiOhRCsTlWJLv);else xZFKsx += wHuDaHWLCYN(GwAbqskckBKRrrHv, PEGxfiOhRCsTlWJLv, QTtQ" ascii
    $s11 = "function KizytTyaxudYwcSJ(YFtzWbfhuREQsotEXdsrdIu,QtYWqZuErWQeMWzQXmO){return YFtzWbfhuREQsotEXdsrdIu.indexOf(QtYWqZuErWQeMWzQXm" ascii
    $s12 = "function OmAAuokiD(lPOqmutHqewHv) {var KgTUDztucbWwXKGkSmXVsylK = BfKiXBWDANCmsdhDWlMhb.join(GDrwP[0]);var GwAbqskckBKRrrHv, PEG" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}