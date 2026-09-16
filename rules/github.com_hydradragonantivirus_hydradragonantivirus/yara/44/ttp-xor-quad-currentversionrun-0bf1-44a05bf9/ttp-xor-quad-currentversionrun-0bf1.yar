rule TTP_XOR_QUAD_CurrentVersionRun_0bf1 {
  strings:
    $key_0bf1 = { 58 9e [2] 7c 90 [2] 57 bc [2] 79 9e [2] 6d 85 [2] 62 9f [2] 7c 82 [2] 7e 83 [2] 65 85 [2] 79 82 [2] 65 ad }

  condition:
    any of them
}