rule TTP_XOR_QUAD_CurrentVersionRun_39f1 {
  strings:
    $key_39f1 = { 6a 9e [2] 4e 90 [2] 65 bc [2] 4b 9e [2] 5f 85 [2] 50 9f [2] 4e 82 [2] 4c 83 [2] 57 85 [2] 4b 82 [2] 57 ad }

  condition:
    any of them
}