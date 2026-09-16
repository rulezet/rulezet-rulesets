rule TTP_XOR_QUAD_CurrentVersionRun_0258 {
  strings:
    $key_0258 = { 51 37 [2] 75 39 [2] 5e 15 [2] 70 37 [2] 64 2c [2] 6b 36 [2] 75 2b [2] 77 2a [2] 6c 2c [2] 70 2b [2] 6c 04 }

  condition:
    any of them
}