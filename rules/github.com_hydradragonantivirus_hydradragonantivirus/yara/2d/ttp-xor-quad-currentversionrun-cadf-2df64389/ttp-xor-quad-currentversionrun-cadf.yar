rule TTP_XOR_QUAD_CurrentVersionRun_cadf {
  strings:
    $key_cadf = { 99 b0 [2] bd be [2] 96 92 [2] b8 b0 [2] ac ab [2] a3 b1 [2] bd ac [2] bf ad [2] a4 ab [2] b8 ac [2] a4 83 }

  condition:
    any of them
}