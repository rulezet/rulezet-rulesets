rule TTP_XOR_QUAD_CurrentVersionRun_cdfc {
  strings:
    $key_cdfc = { 9e 93 [2] ba 9d [2] 91 b1 [2] bf 93 [2] ab 88 [2] a4 92 [2] ba 8f [2] b8 8e [2] a3 88 [2] bf 8f [2] a3 a0 }

  condition:
    any of them
}