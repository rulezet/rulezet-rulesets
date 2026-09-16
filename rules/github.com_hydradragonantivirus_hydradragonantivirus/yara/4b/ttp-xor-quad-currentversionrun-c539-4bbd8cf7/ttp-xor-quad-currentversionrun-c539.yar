rule TTP_XOR_QUAD_CurrentVersionRun_c539 {
  strings:
    $key_c539 = { 96 56 [2] b2 58 [2] 99 74 [2] b7 56 [2] a3 4d [2] ac 57 [2] b2 4a [2] b0 4b [2] ab 4d [2] b7 4a [2] ab 65 }

  condition:
    any of them
}