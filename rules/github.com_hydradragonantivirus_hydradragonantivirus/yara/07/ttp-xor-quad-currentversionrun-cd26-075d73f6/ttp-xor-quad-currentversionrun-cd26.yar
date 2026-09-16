rule TTP_XOR_QUAD_CurrentVersionRun_cd26 {
  strings:
    $key_cd26 = { 9e 49 [2] ba 47 [2] 91 6b [2] bf 49 [2] ab 52 [2] a4 48 [2] ba 55 [2] b8 54 [2] a3 52 [2] bf 55 [2] a3 7a }

  condition:
    any of them
}