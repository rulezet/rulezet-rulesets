rule TTP_XOR_QUAD_CurrentVersionRun_9221 {
  strings:
    $key_9221 = { c1 4e [2] e5 40 [2] ce 6c [2] e0 4e [2] f4 55 [2] fb 4f [2] e5 52 [2] e7 53 [2] fc 55 [2] e0 52 [2] fc 7d }

  condition:
    any of them
}