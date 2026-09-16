rule TTP_XOR_QUAD_CurrentVersionRun_bbbf {
  strings:
    $key_bbbf = { e8 d0 [2] cc de [2] e7 f2 [2] c9 d0 [2] dd cb [2] d2 d1 [2] cc cc [2] ce cd [2] d5 cb [2] c9 cc [2] d5 e3 }

  condition:
    any of them
}