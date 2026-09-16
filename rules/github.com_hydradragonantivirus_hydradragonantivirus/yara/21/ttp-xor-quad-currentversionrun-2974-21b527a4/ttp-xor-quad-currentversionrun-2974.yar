rule TTP_XOR_QUAD_CurrentVersionRun_2974 {
  strings:
    $key_2974 = { 7a 1b [2] 5e 15 [2] 75 39 [2] 5b 1b [2] 4f 00 [2] 40 1a [2] 5e 07 [2] 5c 06 [2] 47 00 [2] 5b 07 [2] 47 28 }

  condition:
    any of them
}