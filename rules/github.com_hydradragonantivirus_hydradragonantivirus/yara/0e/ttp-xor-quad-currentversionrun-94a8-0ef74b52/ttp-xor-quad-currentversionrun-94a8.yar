rule TTP_XOR_QUAD_CurrentVersionRun_94a8 {
  strings:
    $key_94a8 = { c7 c7 [2] e3 c9 [2] c8 e5 [2] e6 c7 [2] f2 dc [2] fd c6 [2] e3 db [2] e1 da [2] fa dc [2] e6 db [2] fa f4 }

  condition:
    any of them
}