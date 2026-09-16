rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_23ef471e7205_748 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash3       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"

  strings:
    $s1  = "0(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";" ascii
    $s2  = "return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(" ascii
    $s3  = "tion f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s4  = "on f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s5  = "rn \"HJm\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(f" ascii
    $s6  = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii
    $s7  = "(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(" ascii
    $s8  = ")(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Br\";})(),(function f000(" ascii
    $s9  = "){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(" ascii
    $s10 = "rn \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s11 = "eturn \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})()" ascii
    $s12 = "Gn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s13 = "function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){re" ascii
    $s14 = "{return \"Br\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})()" ascii
    $s15 = "(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000()" ascii
    $s16 = "Dh\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s17 = "\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function " ascii
    $s18 = "f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"B" ascii
    $s19 = "on f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s20 = ")(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}