rule TTP_XOR_QUAD_CurrentVersionRun_f376 {
  strings:
    $key_f376 = { a0 19 [2] 84 17 [2] af 3b [2] 81 19 [2] 95 02 [2] 9a 18 [2] 84 05 [2] 86 04 [2] 9d 02 [2] 81 05 [2] 9d 2a }

  condition:
    any of them
}