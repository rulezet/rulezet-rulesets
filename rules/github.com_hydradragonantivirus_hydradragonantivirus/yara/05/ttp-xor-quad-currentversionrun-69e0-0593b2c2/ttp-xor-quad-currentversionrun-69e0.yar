rule TTP_XOR_QUAD_CurrentVersionRun_69e0 {
  strings:
    $key_69e0 = { 3a 8f [2] 1e 81 [2] 35 ad [2] 1b 8f [2] 0f 94 [2] 00 8e [2] 1e 93 [2] 1c 92 [2] 07 94 [2] 1b 93 [2] 07 bc }

  condition:
    any of them
}