rule TTP_XOR_QUAD_CurrentVersionRun_9122 {
  strings:
    $key_9122 = { c2 4d [2] e6 43 [2] cd 6f [2] e3 4d [2] f7 56 [2] f8 4c [2] e6 51 [2] e4 50 [2] ff 56 [2] e3 51 [2] ff 7e }

  condition:
    any of them
}