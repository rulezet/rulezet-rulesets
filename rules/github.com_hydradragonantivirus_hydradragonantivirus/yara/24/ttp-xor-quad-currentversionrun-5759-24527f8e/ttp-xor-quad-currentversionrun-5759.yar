rule TTP_XOR_QUAD_CurrentVersionRun_5759 {
  strings:
    $key_5759 = { 04 36 [2] 20 38 [2] 0b 14 [2] 25 36 [2] 31 2d [2] 3e 37 [2] 20 2a [2] 22 2b [2] 39 2d [2] 25 2a [2] 39 05 }

  condition:
    any of them
}