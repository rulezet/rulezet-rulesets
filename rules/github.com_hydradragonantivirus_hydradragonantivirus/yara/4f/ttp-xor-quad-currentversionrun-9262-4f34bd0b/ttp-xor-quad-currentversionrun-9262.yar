rule TTP_XOR_QUAD_CurrentVersionRun_9262 {
  strings:
    $key_9262 = { c1 0d [2] e5 03 [2] ce 2f [2] e0 0d [2] f4 16 [2] fb 0c [2] e5 11 [2] e7 10 [2] fc 16 [2] e0 11 [2] fc 3e }

  condition:
    any of them
}