rule TTP_XOR_QUAD_CurrentVersionRun_5744 {
  strings:
    $key_5744 = { 04 2b [2] 20 25 [2] 0b 09 [2] 25 2b [2] 31 30 [2] 3e 2a [2] 20 37 [2] 22 36 [2] 39 30 [2] 25 37 [2] 39 18 }

  condition:
    any of them
}