rule TTP_XOR_QUAD_CurrentVersionRun_f608 {
  strings:
    $key_f608 = { a5 67 [2] 81 69 [2] aa 45 [2] 84 67 [2] 90 7c [2] 9f 66 [2] 81 7b [2] 83 7a [2] 98 7c [2] 84 7b [2] 98 54 }

  condition:
    any of them
}