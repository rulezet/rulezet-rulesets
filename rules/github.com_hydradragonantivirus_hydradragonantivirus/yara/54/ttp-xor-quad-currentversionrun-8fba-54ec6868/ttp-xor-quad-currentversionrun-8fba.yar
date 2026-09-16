rule TTP_XOR_QUAD_CurrentVersionRun_8fba {
  strings:
    $key_8fba = { dc d5 [2] f8 db [2] d3 f7 [2] fd d5 [2] e9 ce [2] e6 d4 [2] f8 c9 [2] fa c8 [2] e1 ce [2] fd c9 [2] e1 e6 }

  condition:
    any of them
}