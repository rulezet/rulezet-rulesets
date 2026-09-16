rule TTP_XOR_QUAD_CurrentVersionRun_0fe0 {
  strings:
    $key_0fe0 = { 5c 8f [2] 78 81 [2] 53 ad [2] 7d 8f [2] 69 94 [2] 66 8e [2] 78 93 [2] 7a 92 [2] 61 94 [2] 7d 93 [2] 61 bc }

  condition:
    any of them
}