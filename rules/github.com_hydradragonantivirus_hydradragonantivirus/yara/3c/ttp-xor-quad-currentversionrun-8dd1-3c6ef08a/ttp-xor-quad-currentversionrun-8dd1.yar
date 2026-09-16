rule TTP_XOR_QUAD_CurrentVersionRun_8dd1 {
  strings:
    $key_8dd1 = { de be [2] fa b0 [2] d1 9c [2] ff be [2] eb a5 [2] e4 bf [2] fa a2 [2] f8 a3 [2] e3 a5 [2] ff a2 [2] e3 8d }

  condition:
    any of them
}