rule TTP_XOR_QUAD_CurrentVersionRun_dc57 {
  strings:
    $key_dc57 = { 8f 38 [2] ab 36 [2] 80 1a [2] ae 38 [2] ba 23 [2] b5 39 [2] ab 24 [2] a9 25 [2] b2 23 [2] ae 24 [2] b2 0b }

  condition:
    any of them
}