rule _20160921_cb7b906c44a337d403a375918e9db0c5_20160921_eb80446b9cea_4057 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1 = "turn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = "function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s3 = "tion f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii
    $s5 = "{return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s6 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SEo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}