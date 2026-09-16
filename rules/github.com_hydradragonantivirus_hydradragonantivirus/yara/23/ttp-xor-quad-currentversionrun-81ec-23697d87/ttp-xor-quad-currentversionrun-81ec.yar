rule TTP_XOR_QUAD_CurrentVersionRun_81ec {
  strings:
    $key_81ec = { d2 83 [2] f6 8d [2] dd a1 [2] f3 83 [2] e7 98 [2] e8 82 [2] f6 9f [2] f4 9e [2] ef 98 [2] f3 9f [2] ef b0 }

  condition:
    any of them
}