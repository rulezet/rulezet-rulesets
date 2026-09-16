rule TTP_XOR_QUAD_CurrentVersionRun_dc78 {
  strings:
    $key_dc78 = { 8f 17 [2] ab 19 [2] 80 35 [2] ae 17 [2] ba 0c [2] b5 16 [2] ab 0b [2] a9 0a [2] b2 0c [2] ae 0b [2] b2 24 }

  condition:
    any of them
}