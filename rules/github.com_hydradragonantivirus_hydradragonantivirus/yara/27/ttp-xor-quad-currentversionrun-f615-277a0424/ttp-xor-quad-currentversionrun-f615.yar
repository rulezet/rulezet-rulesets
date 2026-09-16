rule TTP_XOR_QUAD_CurrentVersionRun_f615 {
  strings:
    $key_f615 = { a5 7a [2] 81 74 [2] aa 58 [2] 84 7a [2] 90 61 [2] 9f 7b [2] 81 66 [2] 83 67 [2] 98 61 [2] 84 66 [2] 98 49 }

  condition:
    any of them
}