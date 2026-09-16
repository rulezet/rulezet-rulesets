rule TTP_XOR_QUAD_CurrentVersionRun_64e0 {
  strings:
    $key_64e0 = { 37 8f [2] 13 81 [2] 38 ad [2] 16 8f [2] 02 94 [2] 0d 8e [2] 13 93 [2] 11 92 [2] 0a 94 [2] 16 93 [2] 0a bc }

  condition:
    any of them
}