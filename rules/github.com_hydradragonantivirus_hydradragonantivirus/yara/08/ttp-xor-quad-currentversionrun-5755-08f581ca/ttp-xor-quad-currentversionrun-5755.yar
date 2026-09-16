rule TTP_XOR_QUAD_CurrentVersionRun_5755 {
  strings:
    $key_5755 = { 04 3a [2] 20 34 [2] 0b 18 [2] 25 3a [2] 31 21 [2] 3e 3b [2] 20 26 [2] 22 27 [2] 39 21 [2] 25 26 [2] 39 09 }

  condition:
    any of them
}