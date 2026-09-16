rule TTP_XOR_QUAD_CurrentVersionRun_03bf {
  strings:
    $key_03bf = { 50 d0 [2] 74 de [2] 5f f2 [2] 71 d0 [2] 65 cb [2] 6a d1 [2] 74 cc [2] 76 cd [2] 6d cb [2] 71 cc [2] 6d e3 }

  condition:
    any of them
}