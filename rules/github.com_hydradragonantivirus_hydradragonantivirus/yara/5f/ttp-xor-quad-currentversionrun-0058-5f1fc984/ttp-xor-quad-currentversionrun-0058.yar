rule TTP_XOR_QUAD_CurrentVersionRun_0058 {
  strings:
    $key_0058 = { 53 37 [2] 77 39 [2] 5c 15 [2] 72 37 [2] 66 2c [2] 69 36 [2] 77 2b [2] 75 2a [2] 6e 2c [2] 72 2b [2] 6e 04 }

  condition:
    any of them
}