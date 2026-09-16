rule TTP_XOR_QUAD_CurrentVersionRun_20c3 {
  strings:
    $key_20c3 = { 73 ac [2] 57 a2 [2] 7c 8e [2] 52 ac [2] 46 b7 [2] 49 ad [2] 57 b0 [2] 55 b1 [2] 4e b7 [2] 52 b0 [2] 4e 9f }

  condition:
    any of them
}