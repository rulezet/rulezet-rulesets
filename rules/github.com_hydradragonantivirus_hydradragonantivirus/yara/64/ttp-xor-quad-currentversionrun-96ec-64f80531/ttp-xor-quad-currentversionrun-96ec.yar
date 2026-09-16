rule TTP_XOR_QUAD_CurrentVersionRun_96ec {
  strings:
    $key_96ec = { c5 83 [2] e1 8d [2] ca a1 [2] e4 83 [2] f0 98 [2] ff 82 [2] e1 9f [2] e3 9e [2] f8 98 [2] e4 9f [2] f8 b0 }

  condition:
    any of them
}