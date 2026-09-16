rule TTP_XOR_QUAD_CurrentVersionRun_92be {
  strings:
    $key_92be = { c1 d1 [2] e5 df [2] ce f3 [2] e0 d1 [2] f4 ca [2] fb d0 [2] e5 cd [2] e7 cc [2] fc ca [2] e0 cd [2] fc e2 }

  condition:
    any of them
}