rule TTP_XOR_QUAD_CurrentVersionRun_9133 {
  strings:
    $key_9133 = { c2 5c [2] e6 52 [2] cd 7e [2] e3 5c [2] f7 47 [2] f8 5d [2] e6 40 [2] e4 41 [2] ff 47 [2] e3 40 [2] ff 6f }

  condition:
    any of them
}