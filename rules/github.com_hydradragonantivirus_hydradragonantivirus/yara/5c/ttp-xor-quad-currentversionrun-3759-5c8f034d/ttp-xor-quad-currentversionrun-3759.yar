rule TTP_XOR_QUAD_CurrentVersionRun_3759 {
  strings:
    $key_3759 = { 64 36 [2] 40 38 [2] 6b 14 [2] 45 36 [2] 51 2d [2] 5e 37 [2] 40 2a [2] 42 2b [2] 59 2d [2] 45 2a [2] 59 05 }

  condition:
    any of them
}