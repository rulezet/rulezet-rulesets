rule TTP_XOR_QUAD_CurrentVersionRun_95ee {
  strings:
    $key_95ee = { c6 81 [2] e2 8f [2] c9 a3 [2] e7 81 [2] f3 9a [2] fc 80 [2] e2 9d [2] e0 9c [2] fb 9a [2] e7 9d [2] fb b2 }

  condition:
    any of them
}