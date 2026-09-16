rule TTP_XOR_QUAD_CurrentVersionRun_78f7 {
  strings:
    $key_78f7 = { 2b 98 [2] 0f 96 [2] 24 ba [2] 0a 98 [2] 1e 83 [2] 11 99 [2] 0f 84 [2] 0d 85 [2] 16 83 [2] 0a 84 [2] 16 ab }

  condition:
    any of them
}