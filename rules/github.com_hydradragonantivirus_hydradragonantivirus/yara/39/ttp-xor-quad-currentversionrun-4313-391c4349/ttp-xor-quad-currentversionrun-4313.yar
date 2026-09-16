rule TTP_XOR_QUAD_CurrentVersionRun_4313 {
  strings:
    $key_4313 = { 10 7c [2] 34 72 [2] 1f 5e [2] 31 7c [2] 25 67 [2] 2a 7d [2] 34 60 [2] 36 61 [2] 2d 67 [2] 31 60 [2] 2d 4f }

  condition:
    any of them
}