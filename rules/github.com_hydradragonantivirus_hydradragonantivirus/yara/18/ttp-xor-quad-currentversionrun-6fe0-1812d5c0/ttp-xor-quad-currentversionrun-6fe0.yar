rule TTP_XOR_QUAD_CurrentVersionRun_6fe0 {
  strings:
    $key_6fe0 = { 3c 8f [2] 18 81 [2] 33 ad [2] 1d 8f [2] 09 94 [2] 06 8e [2] 18 93 [2] 1a 92 [2] 01 94 [2] 1d 93 [2] 01 bc }

  condition:
    any of them
}