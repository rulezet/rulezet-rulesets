rule TTP_XOR_QUAD_CurrentVersionRun_5745 {
  strings:
    $key_5745 = { 04 2a [2] 20 24 [2] 0b 08 [2] 25 2a [2] 31 31 [2] 3e 2b [2] 20 36 [2] 22 37 [2] 39 31 [2] 25 36 [2] 39 19 }

  condition:
    any of them
}