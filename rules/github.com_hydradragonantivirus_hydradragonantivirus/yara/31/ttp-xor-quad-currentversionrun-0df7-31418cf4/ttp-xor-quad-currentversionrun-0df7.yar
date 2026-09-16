rule TTP_XOR_QUAD_CurrentVersionRun_0df7 {
  strings:
    $key_0df7 = { 5e 98 [2] 7a 96 [2] 51 ba [2] 7f 98 [2] 6b 83 [2] 64 99 [2] 7a 84 [2] 78 85 [2] 63 83 [2] 7f 84 [2] 63 ab }

  condition:
    any of them
}