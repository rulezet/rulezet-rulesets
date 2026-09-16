rule TTP_XOR_QUAD_CurrentVersionRun_09df {
  strings:
    $key_09df = { 5a b0 [2] 7e be [2] 55 92 [2] 7b b0 [2] 6f ab [2] 60 b1 [2] 7e ac [2] 7c ad [2] 67 ab [2] 7b ac [2] 67 83 }

  condition:
    any of them
}