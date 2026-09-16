rule TTP_XOR_QUAD_CurrentVersionRun_91ec {
  strings:
    $key_91ec = { c2 83 [2] e6 8d [2] cd a1 [2] e3 83 [2] f7 98 [2] f8 82 [2] e6 9f [2] e4 9e [2] ff 98 [2] e3 9f [2] ff b0 }

  condition:
    any of them
}