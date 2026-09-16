rule TTP_XOR_QUAD_CurrentVersionRun_9111 {
  strings:
    $key_9111 = { c2 7e [2] e6 70 [2] cd 5c [2] e3 7e [2] f7 65 [2] f8 7f [2] e6 62 [2] e4 63 [2] ff 65 [2] e3 62 [2] ff 4d }

  condition:
    any of them
}