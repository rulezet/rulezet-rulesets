rule TTP_XOR_QUAD_CurrentVersionRun_f245 {
  strings:
    $key_f245 = { a1 2a [2] 85 24 [2] ae 08 [2] 80 2a [2] 94 31 [2] 9b 2b [2] 85 36 [2] 87 37 [2] 9c 31 [2] 80 36 [2] 9c 19 }

  condition:
    any of them
}