rule TTP_XOR_QUAD_CurrentVersionRun_6de0 {
  strings:
    $key_6de0 = { 3e 8f [2] 1a 81 [2] 31 ad [2] 1f 8f [2] 0b 94 [2] 04 8e [2] 1a 93 [2] 18 92 [2] 03 94 [2] 1f 93 [2] 03 bc }

  condition:
    any of them
}