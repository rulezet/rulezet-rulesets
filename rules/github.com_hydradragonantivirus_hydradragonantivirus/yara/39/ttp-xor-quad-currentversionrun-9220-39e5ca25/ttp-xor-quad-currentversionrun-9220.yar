rule TTP_XOR_QUAD_CurrentVersionRun_9220 {
  strings:
    $key_9220 = { c1 4f [2] e5 41 [2] ce 6d [2] e0 4f [2] f4 54 [2] fb 4e [2] e5 53 [2] e7 52 [2] fc 54 [2] e0 53 [2] fc 7c }

  condition:
    any of them
}