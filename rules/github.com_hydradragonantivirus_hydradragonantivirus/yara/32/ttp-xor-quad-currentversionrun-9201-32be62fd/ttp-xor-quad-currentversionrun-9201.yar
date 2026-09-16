rule TTP_XOR_QUAD_CurrentVersionRun_9201 {
  strings:
    $key_9201 = { c1 6e [2] e5 60 [2] ce 4c [2] e0 6e [2] f4 75 [2] fb 6f [2] e5 72 [2] e7 73 [2] fc 75 [2] e0 72 [2] fc 5d }

  condition:
    any of them
}