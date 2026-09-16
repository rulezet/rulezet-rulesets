rule TTP_XOR_QUAD_CurrentVersionRun_e697 {
  strings:
    $key_e697 = { b5 f8 [2] 91 f6 [2] ba da [2] 94 f8 [2] 80 e3 [2] 8f f9 [2] 91 e4 [2] 93 e5 [2] 88 e3 [2] 94 e4 [2] 88 cb }

  condition:
    any of them
}