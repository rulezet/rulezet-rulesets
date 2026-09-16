rule TTP_XOR_QUAD_CurrentVersionRun_2b58 {
  strings:
    $key_2b58 = { 78 37 [2] 5c 39 [2] 77 15 [2] 59 37 [2] 4d 2c [2] 42 36 [2] 5c 2b [2] 5e 2a [2] 45 2c [2] 59 2b [2] 45 04 }

  condition:
    any of them
}