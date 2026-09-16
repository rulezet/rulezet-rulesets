rule TTP_XOR_QUAD_CurrentVersionRun_d7bf {
  strings:
    $key_d7bf = { 84 d0 [2] a0 de [2] 8b f2 [2] a5 d0 [2] b1 cb [2] be d1 [2] a0 cc [2] a2 cd [2] b9 cb [2] a5 cc [2] b9 e3 }

  condition:
    any of them
}