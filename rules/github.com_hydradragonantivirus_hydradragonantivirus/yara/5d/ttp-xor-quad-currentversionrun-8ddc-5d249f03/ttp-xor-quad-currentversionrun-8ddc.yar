rule TTP_XOR_QUAD_CurrentVersionRun_8ddc {
  strings:
    $key_8ddc = { de b3 [2] fa bd [2] d1 91 [2] ff b3 [2] eb a8 [2] e4 b2 [2] fa af [2] f8 ae [2] e3 a8 [2] ff af [2] e3 80 }

  condition:
    any of them
}