rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160921_a65ac281dbfd_2829 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii
    $s2 = "IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s3 = " \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s4 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})()," ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SGs\"" ascii
    $s6 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\"" ascii
    $s7 = "{return \"BMj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}