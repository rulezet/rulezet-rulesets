rule TTP_XOR_QUAD_CurrentVersionRun_dc18 {
  strings:
    $key_dc18 = { 8f 77 [2] ab 79 [2] 80 55 [2] ae 77 [2] ba 6c [2] b5 76 [2] ab 6b [2] a9 6a [2] b2 6c [2] ae 6b [2] b2 44 }

  condition:
    any of them
}