rule TTP_XOR_QUAD_CurrentVersionRun_96e3 {
  strings:
    $key_96e3 = { c5 8c [2] e1 82 [2] ca ae [2] e4 8c [2] f0 97 [2] ff 8d [2] e1 90 [2] e3 91 [2] f8 97 [2] e4 90 [2] f8 bf }

  condition:
    any of them
}