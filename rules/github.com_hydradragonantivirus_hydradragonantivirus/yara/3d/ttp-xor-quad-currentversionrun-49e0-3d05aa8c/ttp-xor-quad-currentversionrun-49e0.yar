rule TTP_XOR_QUAD_CurrentVersionRun_49e0 {
  strings:
    $key_49e0 = { 1a 8f [2] 3e 81 [2] 15 ad [2] 3b 8f [2] 2f 94 [2] 20 8e [2] 3e 93 [2] 3c 92 [2] 27 94 [2] 3b 93 [2] 27 bc }

  condition:
    any of them
}