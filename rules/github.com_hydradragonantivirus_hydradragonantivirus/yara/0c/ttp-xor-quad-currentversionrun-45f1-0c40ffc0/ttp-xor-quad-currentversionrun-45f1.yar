rule TTP_XOR_QUAD_CurrentVersionRun_45f1 {
  strings:
    $key_45f1 = { 16 9e [2] 32 90 [2] 19 bc [2] 37 9e [2] 23 85 [2] 2c 9f [2] 32 82 [2] 30 83 [2] 2b 85 [2] 37 82 [2] 2b ad }

  condition:
    any of them
}