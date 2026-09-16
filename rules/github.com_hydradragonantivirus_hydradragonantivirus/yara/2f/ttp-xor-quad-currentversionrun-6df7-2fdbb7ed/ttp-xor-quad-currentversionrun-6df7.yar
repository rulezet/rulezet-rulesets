rule TTP_XOR_QUAD_CurrentVersionRun_6df7 {
  strings:
    $key_6df7 = { 3e 98 [2] 1a 96 [2] 31 ba [2] 1f 98 [2] 0b 83 [2] 04 99 [2] 1a 84 [2] 18 85 [2] 03 83 [2] 1f 84 [2] 03 ab }

  condition:
    any of them
}