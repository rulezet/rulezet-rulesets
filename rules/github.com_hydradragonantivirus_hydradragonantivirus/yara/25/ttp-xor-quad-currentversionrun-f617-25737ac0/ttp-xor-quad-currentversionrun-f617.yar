rule TTP_XOR_QUAD_CurrentVersionRun_f617 {
  strings:
    $key_f617 = { a5 78 [2] 81 76 [2] aa 5a [2] 84 78 [2] 90 63 [2] 9f 79 [2] 81 64 [2] 83 65 [2] 98 63 [2] 84 64 [2] 98 4b }

  condition:
    any of them
}