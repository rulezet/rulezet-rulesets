rule TTP_XOR_QUAD_CurrentVersionRun_d0bf {
  strings:
    $key_d0bf = { 83 d0 [2] a7 de [2] 8c f2 [2] a2 d0 [2] b6 cb [2] b9 d1 [2] a7 cc [2] a5 cd [2] be cb [2] a2 cc [2] be e3 }

  condition:
    any of them
}