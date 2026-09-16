rule TTP_XOR_QUAD_CurrentVersionRun_08f7 {
  strings:
    $key_08f7 = { 5b 98 [2] 7f 96 [2] 54 ba [2] 7a 98 [2] 6e 83 [2] 61 99 [2] 7f 84 [2] 7d 85 [2] 66 83 [2] 7a 84 [2] 66 ab }

  condition:
    any of them
}