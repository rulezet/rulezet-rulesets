rule TTP_XOR_QUAD_CurrentVersionRun_cd21 {
  strings:
    $key_cd21 = { 9e 4e [2] ba 40 [2] 91 6c [2] bf 4e [2] ab 55 [2] a4 4f [2] ba 52 [2] b8 53 [2] a3 55 [2] bf 52 [2] a3 7d }

  condition:
    any of them
}