rule TTP_XOR_QUAD_CurrentVersionRun_9430 {
  strings:
    $key_9430 = { c7 5f [2] e3 51 [2] c8 7d [2] e6 5f [2] f2 44 [2] fd 5e [2] e3 43 [2] e1 42 [2] fa 44 [2] e6 43 [2] fa 6c }

  condition:
    any of them
}