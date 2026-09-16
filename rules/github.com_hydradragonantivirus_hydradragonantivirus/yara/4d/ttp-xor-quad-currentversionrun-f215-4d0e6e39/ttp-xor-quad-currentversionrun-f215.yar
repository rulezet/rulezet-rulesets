rule TTP_XOR_QUAD_CurrentVersionRun_f215 {
  strings:
    $key_f215 = { a1 7a [2] 85 74 [2] ae 58 [2] 80 7a [2] 94 61 [2] 9b 7b [2] 85 66 [2] 87 67 [2] 9c 61 [2] 80 66 [2] 9c 49 }

  condition:
    any of them
}