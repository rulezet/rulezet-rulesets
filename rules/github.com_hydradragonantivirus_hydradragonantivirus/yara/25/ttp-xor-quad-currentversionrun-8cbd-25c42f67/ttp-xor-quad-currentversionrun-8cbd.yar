rule TTP_XOR_QUAD_CurrentVersionRun_8cbd {
  strings:
    $key_8cbd = { df d2 [2] fb dc [2] d0 f0 [2] fe d2 [2] ea c9 [2] e5 d3 [2] fb ce [2] f9 cf [2] e2 c9 [2] fe ce [2] e2 e1 }

  condition:
    any of them
}