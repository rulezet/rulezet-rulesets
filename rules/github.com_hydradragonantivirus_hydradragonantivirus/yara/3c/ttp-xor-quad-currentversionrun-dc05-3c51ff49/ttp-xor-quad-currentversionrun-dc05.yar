rule TTP_XOR_QUAD_CurrentVersionRun_dc05 {
  strings:
    $key_dc05 = { 8f 6a [2] ab 64 [2] 80 48 [2] ae 6a [2] ba 71 [2] b5 6b [2] ab 76 [2] a9 77 [2] b2 71 [2] ae 76 [2] b2 59 }

  condition:
    any of them
}