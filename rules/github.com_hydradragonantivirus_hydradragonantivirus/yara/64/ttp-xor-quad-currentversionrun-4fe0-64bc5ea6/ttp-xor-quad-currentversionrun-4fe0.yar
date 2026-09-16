rule TTP_XOR_QUAD_CurrentVersionRun_4fe0 {
  strings:
    $key_4fe0 = { 1c 8f [2] 38 81 [2] 13 ad [2] 3d 8f [2] 29 94 [2] 26 8e [2] 38 93 [2] 3a 92 [2] 21 94 [2] 3d 93 [2] 21 bc }

  condition:
    any of them
}