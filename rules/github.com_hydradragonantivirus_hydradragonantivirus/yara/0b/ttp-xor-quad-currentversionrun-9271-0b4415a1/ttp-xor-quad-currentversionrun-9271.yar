rule TTP_XOR_QUAD_CurrentVersionRun_9271 {
  strings:
    $key_9271 = { c1 1e [2] e5 10 [2] ce 3c [2] e0 1e [2] f4 05 [2] fb 1f [2] e5 02 [2] e7 03 [2] fc 05 [2] e0 02 [2] fc 2d }

  condition:
    any of them
}