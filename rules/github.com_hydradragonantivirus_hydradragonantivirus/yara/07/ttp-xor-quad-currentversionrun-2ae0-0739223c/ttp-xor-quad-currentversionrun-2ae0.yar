rule TTP_XOR_QUAD_CurrentVersionRun_2ae0 {
  strings:
    $key_2ae0 = { 79 8f [2] 5d 81 [2] 76 ad [2] 58 8f [2] 4c 94 [2] 43 8e [2] 5d 93 [2] 5f 92 [2] 44 94 [2] 58 93 [2] 44 bc }

  condition:
    any of them
}