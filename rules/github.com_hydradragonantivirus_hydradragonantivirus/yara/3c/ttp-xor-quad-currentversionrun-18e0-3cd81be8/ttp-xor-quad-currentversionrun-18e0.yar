rule TTP_XOR_QUAD_CurrentVersionRun_18e0 {
  strings:
    $key_18e0 = { 4b 8f [2] 6f 81 [2] 44 ad [2] 6a 8f [2] 7e 94 [2] 71 8e [2] 6f 93 [2] 6d 92 [2] 76 94 [2] 6a 93 [2] 76 bc }

  condition:
    any of them
}