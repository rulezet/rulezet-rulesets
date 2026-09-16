rule TTP_XOR_QUAD_CurrentVersionRun_38a8 {
  strings:
    $key_38a8 = { 6b c7 [2] 4f c9 [2] 64 e5 [2] 4a c7 [2] 5e dc [2] 51 c6 [2] 4f db [2] 4d da [2] 56 dc [2] 4a db [2] 56 f4 }

  condition:
    any of them
}