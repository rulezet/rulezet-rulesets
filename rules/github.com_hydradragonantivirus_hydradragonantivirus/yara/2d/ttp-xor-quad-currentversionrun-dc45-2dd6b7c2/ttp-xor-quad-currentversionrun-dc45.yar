rule TTP_XOR_QUAD_CurrentVersionRun_dc45 {
  strings:
    $key_dc45 = { 8f 2a [2] ab 24 [2] 80 08 [2] ae 2a [2] ba 31 [2] b5 2b [2] ab 36 [2] a9 37 [2] b2 31 [2] ae 36 [2] b2 19 }

  condition:
    any of them
}