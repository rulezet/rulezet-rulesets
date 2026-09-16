rule TTP_XOR_QUAD_CurrentVersionRun_cd0c {
  strings:
    $key_cd0c = { 9e 63 [2] ba 6d [2] 91 41 [2] bf 63 [2] ab 78 [2] a4 62 [2] ba 7f [2] b8 7e [2] a3 78 [2] bf 7f [2] a3 50 }

  condition:
    any of them
}