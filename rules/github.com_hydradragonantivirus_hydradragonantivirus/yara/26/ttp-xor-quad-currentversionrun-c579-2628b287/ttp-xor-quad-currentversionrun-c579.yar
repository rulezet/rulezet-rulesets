rule TTP_XOR_QUAD_CurrentVersionRun_c579 {
  strings:
    $key_c579 = { 96 16 [2] b2 18 [2] 99 34 [2] b7 16 [2] a3 0d [2] ac 17 [2] b2 0a [2] b0 0b [2] ab 0d [2] b7 0a [2] ab 25 }

  condition:
    any of them
}