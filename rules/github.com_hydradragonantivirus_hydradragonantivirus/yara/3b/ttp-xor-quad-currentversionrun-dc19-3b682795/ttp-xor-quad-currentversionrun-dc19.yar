rule TTP_XOR_QUAD_CurrentVersionRun_dc19 {
  strings:
    $key_dc19 = { 8f 76 [2] ab 78 [2] 80 54 [2] ae 76 [2] ba 6d [2] b5 77 [2] ab 6a [2] a9 6b [2] b2 6d [2] ae 6a [2] b2 45 }

  condition:
    any of them
}