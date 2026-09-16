rule TTP_XOR_QUAD_CurrentVersionRun_65f1 {
  strings:
    $key_65f1 = { 36 9e [2] 12 90 [2] 39 bc [2] 17 9e [2] 03 85 [2] 0c 9f [2] 12 82 [2] 10 83 [2] 0b 85 [2] 17 82 [2] 0b ad }

  condition:
    any of them
}