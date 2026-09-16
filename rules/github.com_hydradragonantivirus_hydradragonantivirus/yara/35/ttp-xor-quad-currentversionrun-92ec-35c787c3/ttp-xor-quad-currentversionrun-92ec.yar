rule TTP_XOR_QUAD_CurrentVersionRun_92ec {
  strings:
    $key_92ec = { c1 83 [2] e5 8d [2] ce a1 [2] e0 83 [2] f4 98 [2] fb 82 [2] e5 9f [2] e7 9e [2] fc 98 [2] e0 9f [2] fc b0 }

  condition:
    any of them
}