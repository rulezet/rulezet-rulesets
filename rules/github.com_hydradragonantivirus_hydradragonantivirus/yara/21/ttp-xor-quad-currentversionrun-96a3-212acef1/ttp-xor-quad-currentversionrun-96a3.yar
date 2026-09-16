rule TTP_XOR_QUAD_CurrentVersionRun_96a3 {
  strings:
    $key_96a3 = { c5 cc [2] e1 c2 [2] ca ee [2] e4 cc [2] f0 d7 [2] ff cd [2] e1 d0 [2] e3 d1 [2] f8 d7 [2] e4 d0 [2] f8 ff }

  condition:
    any of them
}