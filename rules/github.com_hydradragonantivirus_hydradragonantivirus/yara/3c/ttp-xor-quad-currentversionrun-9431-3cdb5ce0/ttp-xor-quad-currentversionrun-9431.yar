rule TTP_XOR_QUAD_CurrentVersionRun_9431 {
  strings:
    $key_9431 = { c7 5e [2] e3 50 [2] c8 7c [2] e6 5e [2] f2 45 [2] fd 5f [2] e3 42 [2] e1 43 [2] fa 45 [2] e6 42 [2] fa 6d }

  condition:
    any of them
}