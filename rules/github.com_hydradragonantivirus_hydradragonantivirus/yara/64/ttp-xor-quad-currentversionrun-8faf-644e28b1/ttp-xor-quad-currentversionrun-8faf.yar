rule TTP_XOR_QUAD_CurrentVersionRun_8faf {
  strings:
    $key_8faf = { dc c0 [2] f8 ce [2] d3 e2 [2] fd c0 [2] e9 db [2] e6 c1 [2] f8 dc [2] fa dd [2] e1 db [2] fd dc [2] e1 f3 }

  condition:
    any of them
}