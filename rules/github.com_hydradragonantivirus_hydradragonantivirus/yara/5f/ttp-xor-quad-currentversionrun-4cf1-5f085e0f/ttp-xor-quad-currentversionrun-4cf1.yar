rule TTP_XOR_QUAD_CurrentVersionRun_4cf1 {
  strings:
    $key_4cf1 = { 1f 9e [2] 3b 90 [2] 10 bc [2] 3e 9e [2] 2a 85 [2] 25 9f [2] 3b 82 [2] 39 83 [2] 22 85 [2] 3e 82 [2] 22 ad }

  condition:
    any of them
}