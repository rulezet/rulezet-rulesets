rule TTP_XOR_QUAD_CurrentVersionRun_dcdf {
  strings:
    $key_dcdf = { 8f b0 [2] ab be [2] 80 92 [2] ae b0 [2] ba ab [2] b5 b1 [2] ab ac [2] a9 ad [2] b2 ab [2] ae ac [2] b2 83 }

  condition:
    any of them
}