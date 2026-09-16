rule TTP_XOR_QUAD_CurrentVersionRun_dc65 {
  strings:
    $key_dc65 = { 8f 0a [2] ab 04 [2] 80 28 [2] ae 0a [2] ba 11 [2] b5 0b [2] ab 16 [2] a9 17 [2] b2 11 [2] ae 16 [2] b2 39 }

  condition:
    any of them
}