rule TTP_XOR_QUAD_CurrentVersionRun_dc09 {
  strings:
    $key_dc09 = { 8f 66 [2] ab 68 [2] 80 44 [2] ae 66 [2] ba 7d [2] b5 67 [2] ab 7a [2] a9 7b [2] b2 7d [2] ae 7a [2] b2 55 }

  condition:
    any of them
}