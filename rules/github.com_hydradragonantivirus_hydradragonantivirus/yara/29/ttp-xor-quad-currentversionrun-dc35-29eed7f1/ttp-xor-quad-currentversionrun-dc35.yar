rule TTP_XOR_QUAD_CurrentVersionRun_dc35 {
  strings:
    $key_dc35 = { 8f 5a [2] ab 54 [2] 80 78 [2] ae 5a [2] ba 41 [2] b5 5b [2] ab 46 [2] a9 47 [2] b2 41 [2] ae 46 [2] b2 69 }

  condition:
    any of them
}