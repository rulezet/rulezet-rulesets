rule _20160921_02b826231ece268e91633311d2c70554_20160921_46b3ab412369_423 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_46b3ab412369507850a916abad1e6bf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"

  strings:
    $s1  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKp\";})(),(function f0" ascii
    $s2  = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tn\";}" ascii
    $s3  = "on f000(){return \"BMj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s4  = "return \"Go\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s5  = "unction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){ret" ascii
    $s6  = "tion f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"YTp\";})(),(function f000(){retur" ascii
    $s7  = "turn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})()," ascii
    $s8  = "Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(functio" ascii
    $s9  = "rn \"Lp\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s10 = "00(){return \"ZGq\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn" ascii
    $s11 = "turn \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s12 = "(function f000(){return \"PTi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){r" ascii
    $s13 = "function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){r" ascii
    $s14 = "turn \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s15 = "(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";}" ascii
    $s16 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){retu" ascii
    $s17 = "urn \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(fu" ascii
    $s18 = "0(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s19 = "n \"Ml\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s20 = "ion f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}