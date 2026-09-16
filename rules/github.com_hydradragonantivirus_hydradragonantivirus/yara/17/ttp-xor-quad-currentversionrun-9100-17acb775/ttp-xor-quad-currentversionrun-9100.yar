rule TTP_XOR_QUAD_CurrentVersionRun_9100 {
  strings:
    $key_9100 = { c2 6f [2] e6 61 [2] cd 4d [2] e3 6f [2] f7 74 [2] f8 6e [2] e6 73 [2] e4 72 [2] ff 74 [2] e3 73 [2] ff 5c }

  condition:
    any of them
}