rule TTP_XOR_QUAD_CurrentVersionRun_dc2b {
  strings:
    $key_dc2b = { 8f 44 [2] ab 4a [2] 80 66 [2] ae 44 [2] ba 5f [2] b5 45 [2] ab 58 [2] a9 59 [2] b2 5f [2] ae 58 [2] b2 77 }

  condition:
    any of them
}