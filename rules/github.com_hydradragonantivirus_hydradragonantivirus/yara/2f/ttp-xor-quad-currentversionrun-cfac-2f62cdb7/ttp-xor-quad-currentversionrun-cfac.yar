rule TTP_XOR_QUAD_CurrentVersionRun_cfac {
  strings:
    $key_cfac = { 9c c3 [2] b8 cd [2] 93 e1 [2] bd c3 [2] a9 d8 [2] a6 c2 [2] b8 df [2] ba de [2] a1 d8 [2] bd df [2] a1 f0 }

  condition:
    any of them
}