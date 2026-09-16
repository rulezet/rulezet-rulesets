rule TTP_XOR_QUAD_CurrentVersionRun_9141 {
  strings:
    $key_9141 = { c2 2e [2] e6 20 [2] cd 0c [2] e3 2e [2] f7 35 [2] f8 2f [2] e6 32 [2] e4 33 [2] ff 35 [2] e3 32 [2] ff 1d }

  condition:
    any of them
}