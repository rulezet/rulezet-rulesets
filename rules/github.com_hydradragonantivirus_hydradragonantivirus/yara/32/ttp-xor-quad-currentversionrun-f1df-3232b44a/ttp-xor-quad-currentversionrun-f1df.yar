rule TTP_XOR_QUAD_CurrentVersionRun_f1df {
  strings:
    $key_f1df = { a2 b0 [2] 86 be [2] ad 92 [2] 83 b0 [2] 97 ab [2] 98 b1 [2] 86 ac [2] 84 ad [2] 9f ab [2] 83 ac [2] 9f 83 }

  condition:
    any of them
}