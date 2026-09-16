rule TTP_XOR_QUAD_CurrentVersionRun_2ef7 {
  strings:
    $key_2ef7 = { 7d 98 [2] 59 96 [2] 72 ba [2] 5c 98 [2] 48 83 [2] 47 99 [2] 59 84 [2] 5b 85 [2] 40 83 [2] 5c 84 [2] 40 ab }

  condition:
    any of them
}