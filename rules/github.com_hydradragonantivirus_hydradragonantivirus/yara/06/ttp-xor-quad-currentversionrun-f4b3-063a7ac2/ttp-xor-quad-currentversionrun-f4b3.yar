rule TTP_XOR_QUAD_CurrentVersionRun_f4b3 {
  strings:
    $key_f4b3 = { a7 dc [2] 83 d2 [2] a8 fe [2] 86 dc [2] 92 c7 [2] 9d dd [2] 83 c0 [2] 81 c1 [2] 9a c7 [2] 86 c0 [2] 9a ef }

  condition:
    any of them
}