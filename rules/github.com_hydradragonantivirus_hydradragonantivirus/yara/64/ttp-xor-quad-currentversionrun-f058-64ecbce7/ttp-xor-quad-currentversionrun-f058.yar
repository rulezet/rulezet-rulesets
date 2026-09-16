rule TTP_XOR_QUAD_CurrentVersionRun_f058 {
  strings:
    $key_f058 = { a3 37 [2] 87 39 [2] ac 15 [2] 82 37 [2] 96 2c [2] 99 36 [2] 87 2b [2] 85 2a [2] 9e 2c [2] 82 2b [2] 9e 04 }

  condition:
    any of them
}