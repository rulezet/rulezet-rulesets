rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_a1d83c8f2541_120 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash3       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash4       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1  = "on f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s2  = "){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Rh\";})" ascii
    $s3  = "\"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4  = "){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s5  = "turn \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})()," ascii
    $s6  = " \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s7  = "){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})" ascii
    $s8  = "){return \"Nx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s9  = "Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s10 = "on f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s11 = "turn \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})()," ascii
    $s12 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s13 = "Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s14 = "000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Br\"" ascii
    $s15 = "eturn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})()," ascii
    $s16 = "n \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s17 = "turn \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(" ascii
    $s18 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(functio" ascii
    $s19 = "n f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"M" ascii
    $s20 = " f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}