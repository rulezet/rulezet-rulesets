rule TTP_XOR_QUAD_CurrentVersionRun_92f9 {
  strings:
    $key_92f9 = { c1 96 [2] e5 98 [2] ce b4 [2] e0 96 [2] f4 8d [2] fb 97 [2] e5 8a [2] e7 8b [2] fc 8d [2] e0 8a [2] fc a5 }

  condition:
    any of them
}