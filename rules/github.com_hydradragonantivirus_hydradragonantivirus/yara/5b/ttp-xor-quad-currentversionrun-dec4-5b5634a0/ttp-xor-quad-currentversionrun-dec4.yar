rule TTP_XOR_QUAD_CurrentVersionRun_dec4 {
  strings:
    $key_dec4 = { 8d ab [2] a9 a5 [2] 82 89 [2] ac ab [2] b8 b0 [2] b7 aa [2] a9 b7 [2] ab b6 [2] b0 b0 [2] ac b7 [2] b0 98 }

  condition:
    any of them
}