rule TTP_XOR_QUAD_CurrentVersionRun_11c3 {
  strings:
    $key_11c3 = { 42 ac [2] 66 a2 [2] 4d 8e [2] 63 ac [2] 77 b7 [2] 78 ad [2] 66 b0 [2] 64 b1 [2] 7f b7 [2] 63 b0 [2] 7f 9f }

  condition:
    any of them
}