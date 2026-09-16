rule TTP_XOR_QUAD_CurrentVersionRun_57bf {
  strings:
    $key_57bf = { 04 d0 [2] 20 de [2] 0b f2 [2] 25 d0 [2] 31 cb [2] 3e d1 [2] 20 cc [2] 22 cd [2] 39 cb [2] 25 cc [2] 39 e3 }

  condition:
    any of them
}