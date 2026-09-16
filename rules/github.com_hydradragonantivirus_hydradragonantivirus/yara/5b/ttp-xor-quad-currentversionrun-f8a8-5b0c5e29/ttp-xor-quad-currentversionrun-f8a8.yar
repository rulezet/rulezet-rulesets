rule TTP_XOR_QUAD_CurrentVersionRun_f8a8 {
  strings:
    $key_f8a8 = { ab c7 [2] 8f c9 [2] a4 e5 [2] 8a c7 [2] 9e dc [2] 91 c6 [2] 8f db [2] 8d da [2] 96 dc [2] 8a db [2] 96 f4 }

  condition:
    any of them
}