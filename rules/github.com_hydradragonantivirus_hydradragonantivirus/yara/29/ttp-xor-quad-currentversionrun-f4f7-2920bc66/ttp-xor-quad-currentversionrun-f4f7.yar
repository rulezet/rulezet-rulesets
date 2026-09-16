rule TTP_XOR_QUAD_CurrentVersionRun_f4f7 {
  strings:
    $key_f4f7 = { a7 98 [2] 83 96 [2] a8 ba [2] 86 98 [2] 92 83 [2] 9d 99 [2] 83 84 [2] 81 85 [2] 9a 83 [2] 86 84 [2] 9a ab }

  condition:
    any of them
}