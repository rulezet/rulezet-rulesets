rule TTP_XOR_QUAD_CurrentVersionRun_f04b {
  strings:
    $key_f04b = { a3 24 [2] 87 2a [2] ac 06 [2] 82 24 [2] 96 3f [2] 99 25 [2] 87 38 [2] 85 39 [2] 9e 3f [2] 82 38 [2] 9e 17 }

  condition:
    any of them
}