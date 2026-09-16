rule TTP_XOR_QUAD_CurrentVersionRun_04e0 {
  strings:
    $key_04e0 = { 57 8f [2] 73 81 [2] 58 ad [2] 76 8f [2] 62 94 [2] 6d 8e [2] 73 93 [2] 71 92 [2] 6a 94 [2] 76 93 [2] 6a bc }

  condition:
    any of them
}