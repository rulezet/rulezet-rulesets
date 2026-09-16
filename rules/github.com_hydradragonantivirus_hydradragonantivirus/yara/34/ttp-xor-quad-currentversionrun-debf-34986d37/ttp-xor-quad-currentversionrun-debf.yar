rule TTP_XOR_QUAD_CurrentVersionRun_debf {
  strings:
    $key_debf = { 8d d0 [2] a9 de [2] 82 f2 [2] ac d0 [2] b8 cb [2] b7 d1 [2] a9 cc [2] ab cd [2] b0 cb [2] ac cc [2] b0 e3 }

  condition:
    any of them
}