rule TTP_XOR_QUAD_CurrentVersionRun_efb5 {
  strings:
    $key_efb5 = { bc da [2] 98 d4 [2] b3 f8 [2] 9d da [2] 89 c1 [2] 86 db [2] 98 c6 [2] 9a c7 [2] 81 c1 [2] 9d c6 [2] 81 e9 }

  condition:
    any of them
}