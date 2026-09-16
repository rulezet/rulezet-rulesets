rule TTP_XOR_QUAD_CurrentVersionRun_24df {
  strings:
    $key_24df = { 77 b0 [2] 53 be [2] 78 92 [2] 56 b0 [2] 42 ab [2] 4d b1 [2] 53 ac [2] 51 ad [2] 4a ab [2] 56 ac [2] 4a 83 }

  condition:
    any of them
}