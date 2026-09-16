rule TTP_XOR_QUAD_CurrentVersionRun_54e0 {
  strings:
    $key_54e0 = { 07 8f [2] 23 81 [2] 08 ad [2] 26 8f [2] 32 94 [2] 3d 8e [2] 23 93 [2] 21 92 [2] 3a 94 [2] 26 93 [2] 3a bc }

  condition:
    any of them
}