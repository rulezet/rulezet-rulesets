rule TTP_XOR_QUAD_CurrentVersionRun_6244 {
  strings:
    $key_6244 = { 31 2b [2] 15 25 [2] 3e 09 [2] 10 2b [2] 04 30 [2] 0b 2a [2] 15 37 [2] 17 36 [2] 0c 30 [2] 10 37 [2] 0c 18 }

  condition:
    any of them
}