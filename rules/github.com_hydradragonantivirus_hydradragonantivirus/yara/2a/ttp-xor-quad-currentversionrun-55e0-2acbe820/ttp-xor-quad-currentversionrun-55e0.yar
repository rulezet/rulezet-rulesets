rule TTP_XOR_QUAD_CurrentVersionRun_55e0 {
  strings:
    $key_55e0 = { 06 8f [2] 22 81 [2] 09 ad [2] 27 8f [2] 33 94 [2] 3c 8e [2] 22 93 [2] 20 92 [2] 3b 94 [2] 27 93 [2] 3b bc }

  condition:
    any of them
}