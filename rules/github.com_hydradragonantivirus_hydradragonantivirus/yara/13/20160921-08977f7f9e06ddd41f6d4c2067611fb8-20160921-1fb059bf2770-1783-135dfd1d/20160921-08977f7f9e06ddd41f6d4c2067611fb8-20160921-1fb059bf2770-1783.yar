rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_1fb059bf2770_1783 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_a2977e58d35241f07c3f294ca2097899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash3       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"

  strings:
    $s1  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})" ascii
    $s2  = "unction f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){ret" ascii
    $s3  = "Db\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(functio" ascii
    $s4  = "return \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKl\";})()" ascii
    $s5  = "f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo" ascii
    $s6  = "on f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return " ascii
    $s7  = "0(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\"" ascii
    $s8  = "rn \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(f" ascii
    $s9  = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(" ascii
    $s10 = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}