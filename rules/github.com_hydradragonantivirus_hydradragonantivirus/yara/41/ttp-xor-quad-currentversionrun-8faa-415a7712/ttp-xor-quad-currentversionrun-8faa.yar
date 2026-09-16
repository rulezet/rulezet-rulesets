rule TTP_XOR_QUAD_CurrentVersionRun_8faa {
  strings:
    $key_8faa = { dc c5 [2] f8 cb [2] d3 e7 [2] fd c5 [2] e9 de [2] e6 c4 [2] f8 d9 [2] fa d8 [2] e1 de [2] fd d9 [2] e1 f6 }

  condition:
    any of them
}