rule TTP_XOR_QUAD_CurrentVersionRun_f626 {
  strings:
    $key_f626 = { a5 49 [2] 81 47 [2] aa 6b [2] 84 49 [2] 90 52 [2] 9f 48 [2] 81 55 [2] 83 54 [2] 98 52 [2] 84 55 [2] 98 7a }

  condition:
    any of them
}