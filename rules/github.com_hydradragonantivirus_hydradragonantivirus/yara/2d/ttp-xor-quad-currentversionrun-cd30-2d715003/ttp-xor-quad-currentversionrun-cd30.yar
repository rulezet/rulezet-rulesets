rule TTP_XOR_QUAD_CurrentVersionRun_cd30 {
  strings:
    $key_cd30 = { 9e 5f [2] ba 51 [2] 91 7d [2] bf 5f [2] ab 44 [2] a4 5e [2] ba 43 [2] b8 42 [2] a3 44 [2] bf 43 [2] a3 6c }

  condition:
    any of them
}