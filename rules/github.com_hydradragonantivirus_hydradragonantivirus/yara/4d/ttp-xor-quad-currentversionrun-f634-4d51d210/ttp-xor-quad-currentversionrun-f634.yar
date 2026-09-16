rule TTP_XOR_QUAD_CurrentVersionRun_f634 {
  strings:
    $key_f634 = { a5 5b [2] 81 55 [2] aa 79 [2] 84 5b [2] 90 40 [2] 9f 5a [2] 81 47 [2] 83 46 [2] 98 40 [2] 84 47 [2] 98 68 }

  condition:
    any of them
}