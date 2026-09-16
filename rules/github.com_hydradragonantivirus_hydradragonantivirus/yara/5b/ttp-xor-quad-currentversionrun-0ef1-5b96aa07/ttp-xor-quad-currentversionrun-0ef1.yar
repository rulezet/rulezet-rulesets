rule TTP_XOR_QUAD_CurrentVersionRun_0ef1 {
  strings:
    $key_0ef1 = { 5d 9e [2] 79 90 [2] 52 bc [2] 7c 9e [2] 68 85 [2] 67 9f [2] 79 82 [2] 7b 83 [2] 60 85 [2] 7c 82 [2] 60 ad }

  condition:
    any of them
}