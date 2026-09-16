rule TTP_XOR_QUAD_CurrentVersionRun_9176 {
  strings:
    $key_9176 = { c2 19 [2] e6 17 [2] cd 3b [2] e3 19 [2] f7 02 [2] f8 18 [2] e6 05 [2] e4 04 [2] ff 02 [2] e3 05 [2] ff 2a }

  condition:
    any of them
}