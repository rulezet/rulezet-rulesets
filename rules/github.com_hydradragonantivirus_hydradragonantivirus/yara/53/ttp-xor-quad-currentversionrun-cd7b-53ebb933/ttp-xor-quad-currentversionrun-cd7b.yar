rule TTP_XOR_QUAD_CurrentVersionRun_cd7b {
  strings:
    $key_cd7b = { 9e 14 [2] ba 1a [2] 91 36 [2] bf 14 [2] ab 0f [2] a4 15 [2] ba 08 [2] b8 09 [2] a3 0f [2] bf 08 [2] a3 27 }

  condition:
    any of them
}