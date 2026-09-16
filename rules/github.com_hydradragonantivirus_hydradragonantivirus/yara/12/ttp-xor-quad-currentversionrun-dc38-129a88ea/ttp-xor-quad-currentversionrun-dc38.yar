rule TTP_XOR_QUAD_CurrentVersionRun_dc38 {
  strings:
    $key_dc38 = { 8f 57 [2] ab 59 [2] 80 75 [2] ae 57 [2] ba 4c [2] b5 56 [2] ab 4b [2] a9 4a [2] b2 4c [2] ae 4b [2] b2 64 }

  condition:
    any of them
}