rule TTP_XOR_QUAD_CurrentVersionRun_9261 {
  strings:
    $key_9261 = { c1 0e [2] e5 00 [2] ce 2c [2] e0 0e [2] f4 15 [2] fb 0f [2] e5 12 [2] e7 13 [2] fc 15 [2] e0 12 [2] fc 3d }

  condition:
    any of them
}