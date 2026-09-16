rule TTP_XOR_QUAD_CurrentVersionRun_92fd {
  strings:
    $key_92fd = { c1 92 [2] e5 9c [2] ce b0 [2] e0 92 [2] f4 89 [2] fb 93 [2] e5 8e [2] e7 8f [2] fc 89 [2] e0 8e [2] fc a1 }

  condition:
    any of them
}