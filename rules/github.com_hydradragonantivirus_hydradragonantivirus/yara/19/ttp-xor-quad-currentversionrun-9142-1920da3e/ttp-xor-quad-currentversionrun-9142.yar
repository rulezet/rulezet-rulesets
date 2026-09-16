rule TTP_XOR_QUAD_CurrentVersionRun_9142 {
  strings:
    $key_9142 = { c2 2d [2] e6 23 [2] cd 0f [2] e3 2d [2] f7 36 [2] f8 2c [2] e6 31 [2] e4 30 [2] ff 36 [2] e3 31 [2] ff 1e }

  condition:
    any of them
}