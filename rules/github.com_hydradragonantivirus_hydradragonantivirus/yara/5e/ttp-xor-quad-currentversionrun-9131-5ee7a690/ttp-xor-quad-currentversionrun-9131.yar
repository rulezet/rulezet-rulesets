rule TTP_XOR_QUAD_CurrentVersionRun_9131 {
  strings:
    $key_9131 = { c2 5e [2] e6 50 [2] cd 7c [2] e3 5e [2] f7 45 [2] f8 5f [2] e6 42 [2] e4 43 [2] ff 45 [2] e3 42 [2] ff 6d }

  condition:
    any of them
}