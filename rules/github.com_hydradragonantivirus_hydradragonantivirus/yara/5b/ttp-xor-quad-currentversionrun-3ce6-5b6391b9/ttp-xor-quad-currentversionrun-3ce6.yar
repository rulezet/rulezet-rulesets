rule TTP_XOR_QUAD_CurrentVersionRun_3ce6 {
  strings:
    $key_3ce6 = { 6f 89 [2] 4b 87 [2] 60 ab [2] 4e 89 [2] 5a 92 [2] 55 88 [2] 4b 95 [2] 49 94 [2] 52 92 [2] 4e 95 [2] 52 ba }

  condition:
    any of them
}