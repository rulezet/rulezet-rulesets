rule TTP_XOR_QUAD_CurrentVersionRun_cdfb {
  strings:
    $key_cdfb = { 9e 94 [2] ba 9a [2] 91 b6 [2] bf 94 [2] ab 8f [2] a4 95 [2] ba 88 [2] b8 89 [2] a3 8f [2] bf 88 [2] a3 a7 }

  condition:
    any of them
}