rule TTP_XOR_QUAD_CurrentVersionRun_95ec {
  strings:
    $key_95ec = { c6 83 [2] e2 8d [2] c9 a1 [2] e7 83 [2] f3 98 [2] fc 82 [2] e2 9f [2] e0 9e [2] fb 98 [2] e7 9f [2] fb b0 }

  condition:
    any of them
}