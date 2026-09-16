rule TTP_XOR_QUAD_CurrentVersionRun_7af7 {
  strings:
    $key_7af7 = { 29 98 [2] 0d 96 [2] 26 ba [2] 08 98 [2] 1c 83 [2] 13 99 [2] 0d 84 [2] 0f 85 [2] 14 83 [2] 08 84 [2] 14 ab }

  condition:
    any of them
}