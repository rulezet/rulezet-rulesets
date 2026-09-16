rule TTP_XOR_QUAD_CurrentVersionRun_c565 {
  strings:
    $key_c565 = { 96 0a [2] b2 04 [2] 99 28 [2] b7 0a [2] a3 11 [2] ac 0b [2] b2 16 [2] b0 17 [2] ab 11 [2] b7 16 [2] ab 39 }

  condition:
    any of them
}