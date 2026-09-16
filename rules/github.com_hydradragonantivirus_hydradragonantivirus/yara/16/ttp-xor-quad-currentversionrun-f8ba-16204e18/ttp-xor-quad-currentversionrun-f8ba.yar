rule TTP_XOR_QUAD_CurrentVersionRun_f8ba {
  strings:
    $key_f8ba = { ab d5 [2] 8f db [2] a4 f7 [2] 8a d5 [2] 9e ce [2] 91 d4 [2] 8f c9 [2] 8d c8 [2] 96 ce [2] 8a c9 [2] 96 e6 }

  condition:
    any of them
}