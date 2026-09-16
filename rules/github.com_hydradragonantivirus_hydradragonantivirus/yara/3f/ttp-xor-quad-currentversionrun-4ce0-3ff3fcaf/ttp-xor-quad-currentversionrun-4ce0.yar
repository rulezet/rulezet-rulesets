rule TTP_XOR_QUAD_CurrentVersionRun_4ce0 {
  strings:
    $key_4ce0 = { 1f 8f [2] 3b 81 [2] 10 ad [2] 3e 8f [2] 2a 94 [2] 25 8e [2] 3b 93 [2] 39 92 [2] 22 94 [2] 3e 93 [2] 22 bc }

  condition:
    any of them
}