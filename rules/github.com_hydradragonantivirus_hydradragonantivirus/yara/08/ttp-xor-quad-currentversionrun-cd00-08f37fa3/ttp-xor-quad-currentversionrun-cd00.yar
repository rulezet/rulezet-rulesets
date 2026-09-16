rule TTP_XOR_QUAD_CurrentVersionRun_cd00 {
  strings:
    $key_cd00 = { 9e 6f [2] ba 61 [2] 91 4d [2] bf 6f [2] ab 74 [2] a4 6e [2] ba 73 [2] b8 72 [2] a3 74 [2] bf 73 [2] a3 5c }

  condition:
    any of them
}