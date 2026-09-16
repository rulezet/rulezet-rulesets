rule TTP_XOR_QUAD_CurrentVersionRun_18f1 {
  strings:
    $key_18f1 = { 4b 9e [2] 6f 90 [2] 44 bc [2] 6a 9e [2] 7e 85 [2] 71 9f [2] 6f 82 [2] 6d 83 [2] 76 85 [2] 6a 82 [2] 76 ad }

  condition:
    any of them
}