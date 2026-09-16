rule TTP_XOR_QUAD_CurrentVersionRun_9251 {
  strings:
    $key_9251 = { c1 3e [2] e5 30 [2] ce 1c [2] e0 3e [2] f4 25 [2] fb 3f [2] e5 22 [2] e7 23 [2] fc 25 [2] e0 22 [2] fc 0d }

  condition:
    any of them
}