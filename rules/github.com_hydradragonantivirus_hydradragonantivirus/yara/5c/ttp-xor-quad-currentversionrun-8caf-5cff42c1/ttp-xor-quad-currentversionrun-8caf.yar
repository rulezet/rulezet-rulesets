rule TTP_XOR_QUAD_CurrentVersionRun_8caf {
  strings:
    $key_8caf = { df c0 [2] fb ce [2] d0 e2 [2] fe c0 [2] ea db [2] e5 c1 [2] fb dc [2] f9 dd [2] e2 db [2] fe dc [2] e2 f3 }

  condition:
    any of them
}