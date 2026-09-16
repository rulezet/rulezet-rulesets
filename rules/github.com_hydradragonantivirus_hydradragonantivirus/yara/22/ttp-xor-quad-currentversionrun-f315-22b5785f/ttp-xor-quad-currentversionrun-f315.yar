rule TTP_XOR_QUAD_CurrentVersionRun_f315 {
  strings:
    $key_f315 = { a0 7a [2] 84 74 [2] af 58 [2] 81 7a [2] 95 61 [2] 9a 7b [2] 84 66 [2] 86 67 [2] 9d 61 [2] 81 66 [2] 9d 49 }

  condition:
    any of them
}