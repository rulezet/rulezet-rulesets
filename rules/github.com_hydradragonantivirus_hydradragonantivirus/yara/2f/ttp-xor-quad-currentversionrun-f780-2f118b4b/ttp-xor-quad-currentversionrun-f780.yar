rule TTP_XOR_QUAD_CurrentVersionRun_f780 {
  strings:
    $key_f780 = { a4 ef [2] 80 e1 [2] ab cd [2] 85 ef [2] 91 f4 [2] 9e ee [2] 80 f3 [2] 82 f2 [2] 99 f4 [2] 85 f3 [2] 99 dc }

  condition:
    any of them
}