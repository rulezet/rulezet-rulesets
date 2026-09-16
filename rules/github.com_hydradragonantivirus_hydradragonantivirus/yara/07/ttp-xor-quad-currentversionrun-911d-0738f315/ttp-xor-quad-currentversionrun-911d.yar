rule TTP_XOR_QUAD_CurrentVersionRun_911d {
  strings:
    $key_911d = { c2 72 [2] e6 7c [2] cd 50 [2] e3 72 [2] f7 69 [2] f8 73 [2] e6 6e [2] e4 6f [2] ff 69 [2] e3 6e [2] ff 41 }

  condition:
    any of them
}