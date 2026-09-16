rule TTP_XOR_QUAD_CurrentVersionRun_f4b4 {
  strings:
    $key_f4b4 = { a7 db [2] 83 d5 [2] a8 f9 [2] 86 db [2] 92 c0 [2] 9d da [2] 83 c7 [2] 81 c6 [2] 9a c0 [2] 86 c7 [2] 9a e8 }

  condition:
    any of them
}