rule TTP_XOR_QUAD_CurrentVersionRun_910d {
  strings:
    $key_910d = { c2 62 [2] e6 6c [2] cd 40 [2] e3 62 [2] f7 79 [2] f8 63 [2] e6 7e [2] e4 7f [2] ff 79 [2] e3 7e [2] ff 51 }

  condition:
    any of them
}