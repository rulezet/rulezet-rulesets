rule TTP_XOR_QUAD_CurrentVersionRun_9253 {
  strings:
    $key_9253 = { c1 3c [2] e5 32 [2] ce 1e [2] e0 3c [2] f4 27 [2] fb 3d [2] e5 20 [2] e7 21 [2] fc 27 [2] e0 20 [2] fc 0f }

  condition:
    any of them
}