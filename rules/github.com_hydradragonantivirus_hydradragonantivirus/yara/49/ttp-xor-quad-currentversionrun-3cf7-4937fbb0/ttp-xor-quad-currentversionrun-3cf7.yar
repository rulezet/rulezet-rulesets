rule TTP_XOR_QUAD_CurrentVersionRun_3cf7 {
  strings:
    $key_3cf7 = { 6f 98 [2] 4b 96 [2] 60 ba [2] 4e 98 [2] 5a 83 [2] 55 99 [2] 4b 84 [2] 49 85 [2] 52 83 [2] 4e 84 [2] 52 ab }

  condition:
    any of them
}