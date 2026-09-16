rule TTP_XOR_QUAD_CurrentVersionRun_dbb4 {
  strings:
    $key_dbb4 = { 88 db [2] ac d5 [2] 87 f9 [2] a9 db [2] bd c0 [2] b2 da [2] ac c7 [2] ae c6 [2] b5 c0 [2] a9 c7 [2] b5 e8 }

  condition:
    any of them
}