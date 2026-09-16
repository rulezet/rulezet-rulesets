rule TTP_XOR_QUAD_CurrentVersionRun_7bf1 {
  strings:
    $key_7bf1 = { 28 9e [2] 0c 90 [2] 27 bc [2] 09 9e [2] 1d 85 [2] 12 9f [2] 0c 82 [2] 0e 83 [2] 15 85 [2] 09 82 [2] 15 ad }

  condition:
    any of them
}