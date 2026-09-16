rule TTP_XOR_QUAD_CurrentVersionRun_65e0 {
  strings:
    $key_65e0 = { 36 8f [2] 12 81 [2] 39 ad [2] 17 8f [2] 03 94 [2] 0c 8e [2] 12 93 [2] 10 92 [2] 0b 94 [2] 17 93 [2] 0b bc }

  condition:
    any of them
}