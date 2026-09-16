rule TTP_XOR_QUAD_CurrentVersionRun_64cf {
  strings:
    $key_64cf = { 37 a0 [2] 13 ae [2] 38 82 [2] 16 a0 [2] 02 bb [2] 0d a1 [2] 13 bc [2] 11 bd [2] 0a bb [2] 16 bc [2] 0a 93 }

  condition:
    any of them
}