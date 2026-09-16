rule TTP_XOR_QUAD_CurrentVersionRun_dc0b {
  strings:
    $key_dc0b = { 8f 64 [2] ab 6a [2] 80 46 [2] ae 64 [2] ba 7f [2] b5 65 [2] ab 78 [2] a9 79 [2] b2 7f [2] ae 78 [2] b2 57 }

  condition:
    any of them
}