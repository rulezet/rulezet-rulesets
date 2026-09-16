rule TTP_XOR_QUAD_CurrentVersionRun_9102 {
  strings:
    $key_9102 = { c2 6d [2] e6 63 [2] cd 4f [2] e3 6d [2] f7 76 [2] f8 6c [2] e6 71 [2] e4 70 [2] ff 76 [2] e3 71 [2] ff 5e }

  condition:
    any of them
}