rule TTP_XOR_QUAD_CurrentVersionRun_fabf {
  strings:
    $key_fabf = { a9 d0 [2] 8d de [2] a6 f2 [2] 88 d0 [2] 9c cb [2] 93 d1 [2] 8d cc [2] 8f cd [2] 94 cb [2] 88 cc [2] 94 e3 }

  condition:
    any of them
}