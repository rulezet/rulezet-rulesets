rule TTP_XOR_QUAD_CurrentVersionRun_2fe0 {
  strings:
    $key_2fe0 = { 7c 8f [2] 58 81 [2] 73 ad [2] 5d 8f [2] 49 94 [2] 46 8e [2] 58 93 [2] 5a 92 [2] 41 94 [2] 5d 93 [2] 41 bc }

  condition:
    any of them
}