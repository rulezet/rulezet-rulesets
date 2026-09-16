rule TTP_XOR_QUAD_CurrentVersionRun_23bf {
  strings:
    $key_23bf = { 70 d0 [2] 54 de [2] 7f f2 [2] 51 d0 [2] 45 cb [2] 4a d1 [2] 54 cc [2] 56 cd [2] 4d cb [2] 51 cc [2] 4d e3 }

  condition:
    any of them
}