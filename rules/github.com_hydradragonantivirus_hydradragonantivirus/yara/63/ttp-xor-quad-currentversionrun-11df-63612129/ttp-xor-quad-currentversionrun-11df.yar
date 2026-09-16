rule TTP_XOR_QUAD_CurrentVersionRun_11df {
  strings:
    $key_11df = { 42 b0 [2] 66 be [2] 4d 92 [2] 63 b0 [2] 77 ab [2] 78 b1 [2] 66 ac [2] 64 ad [2] 7f ab [2] 63 ac [2] 7f 83 }

  condition:
    any of them
}