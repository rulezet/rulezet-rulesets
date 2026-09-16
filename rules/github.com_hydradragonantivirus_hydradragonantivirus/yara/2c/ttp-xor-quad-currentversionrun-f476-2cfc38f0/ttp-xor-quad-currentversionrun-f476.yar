rule TTP_XOR_QUAD_CurrentVersionRun_f476 {
  strings:
    $key_f476 = { a7 19 [2] 83 17 [2] a8 3b [2] 86 19 [2] 92 02 [2] 9d 18 [2] 83 05 [2] 81 04 [2] 9a 02 [2] 86 05 [2] 9a 2a }

  condition:
    any of them
}