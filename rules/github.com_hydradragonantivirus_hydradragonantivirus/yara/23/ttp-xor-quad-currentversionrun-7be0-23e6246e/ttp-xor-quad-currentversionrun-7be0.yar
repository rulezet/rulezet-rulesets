rule TTP_XOR_QUAD_CurrentVersionRun_7be0 {
  strings:
    $key_7be0 = { 28 8f [2] 0c 81 [2] 27 ad [2] 09 8f [2] 1d 94 [2] 12 8e [2] 0c 93 [2] 0e 92 [2] 15 94 [2] 09 93 [2] 15 bc }

  condition:
    any of them
}