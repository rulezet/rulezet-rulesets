rule TTP_XOR_QUAD_CurrentVersionRun_cdad {
  strings:
    $key_cdad = { 9e c2 [2] ba cc [2] 91 e0 [2] bf c2 [2] ab d9 [2] a4 c3 [2] ba de [2] b8 df [2] a3 d9 [2] bf de [2] a3 f1 }

  condition:
    any of them
}