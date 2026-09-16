rule _20160921_aed247f3d2282ef44bd04021d1a47ef8_20160921_b9bf4d000983_144 {
  meta:
    description = "datamaliciousorder - from files 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash2       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"

  strings:
    $s1  = "n f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2  = "rn \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Rh\";})(),(fu" ascii
    $s3  = "0(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s4  = "tion f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){r" ascii
    $s6  = "\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s7  = "00(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn" ascii
    $s8  = "){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})" ascii
    $s9  = "n f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GG" ascii
    $s10 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){" ascii
    $s11 = "urn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s12 = "(),(function f000(){return \"Ot\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii
    $s13 = "0(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\"" ascii
    $s14 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UE" ascii
    $s15 = "\"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s16 = "(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s17 = "f000(){return \"Vj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn" ascii
    $s18 = "eturn \"Sj\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})()," ascii
    $s19 = "ction f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s20 = "tion f000(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}