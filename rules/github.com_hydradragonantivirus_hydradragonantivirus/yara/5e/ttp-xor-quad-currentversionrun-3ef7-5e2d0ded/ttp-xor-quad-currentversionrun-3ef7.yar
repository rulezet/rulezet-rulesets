rule TTP_XOR_QUAD_CurrentVersionRun_3ef7 {
  strings:
    $key_3ef7 = { 6d 98 [2] 49 96 [2] 62 ba [2] 4c 98 [2] 58 83 [2] 57 99 [2] 49 84 [2] 4b 85 [2] 50 83 [2] 4c 84 [2] 50 ab }

  condition:
    any of them
}