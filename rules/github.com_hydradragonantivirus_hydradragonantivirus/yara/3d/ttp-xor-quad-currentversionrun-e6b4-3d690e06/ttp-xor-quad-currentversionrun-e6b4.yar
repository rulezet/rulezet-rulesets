rule TTP_XOR_QUAD_CurrentVersionRun_e6b4 {
  strings:
    $key_e6b4 = { b5 db [2] 91 d5 [2] ba f9 [2] 94 db [2] 80 c0 [2] 8f da [2] 91 c7 [2] 93 c6 [2] 88 c0 [2] 94 c7 [2] 88 e8 }

  condition:
    any of them
}