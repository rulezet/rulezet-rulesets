rule TTP_XOR_QUAD_CurrentVersionRun_03e0 {
  strings:
    $key_03e0 = { 50 8f [2] 74 81 [2] 5f ad [2] 71 8f [2] 65 94 [2] 6a 8e [2] 74 93 [2] 76 92 [2] 6d 94 [2] 71 93 [2] 6d bc }

  condition:
    any of them
}