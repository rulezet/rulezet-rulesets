rule TTP_XOR_QUAD_CurrentVersionRun_c2f5 {
  strings:
    $key_c2f5 = { 91 9a [2] b5 94 [2] 9e b8 [2] b0 9a [2] a4 81 [2] ab 9b [2] b5 86 [2] b7 87 [2] ac 81 [2] b0 86 [2] ac a9 }

  condition:
    any of them
}