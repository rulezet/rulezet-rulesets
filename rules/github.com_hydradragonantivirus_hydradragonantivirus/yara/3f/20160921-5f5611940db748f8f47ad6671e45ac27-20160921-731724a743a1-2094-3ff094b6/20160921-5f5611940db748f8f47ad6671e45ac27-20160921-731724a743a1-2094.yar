rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_731724a743a1_2094 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "n f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Q" ascii
    $s2 = "000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp" ascii
    $s3 = "turn \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})()" ascii
    $s4 = "(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){r" ascii
    $s5 = "nction f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii
    $s6 = ";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f0" ascii
    $s7 = "n f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"M" ascii
    $s8 = "eturn \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})()," ascii
    $s9 = "),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}