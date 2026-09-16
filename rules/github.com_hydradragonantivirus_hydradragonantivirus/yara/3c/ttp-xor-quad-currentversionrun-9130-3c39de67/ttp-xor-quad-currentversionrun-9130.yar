rule TTP_XOR_QUAD_CurrentVersionRun_9130 {
  strings:
    $key_9130 = { c2 5f [2] e6 51 [2] cd 7d [2] e3 5f [2] f7 44 [2] f8 5e [2] e6 43 [2] e4 42 [2] ff 44 [2] e3 43 [2] ff 6c }

  condition:
    any of them
}