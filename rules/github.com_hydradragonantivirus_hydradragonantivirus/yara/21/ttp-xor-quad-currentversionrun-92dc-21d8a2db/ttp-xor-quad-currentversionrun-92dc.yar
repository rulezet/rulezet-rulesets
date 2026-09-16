rule TTP_XOR_QUAD_CurrentVersionRun_92dc {
  strings:
    $key_92dc = { c1 b3 [2] e5 bd [2] ce 91 [2] e0 b3 [2] f4 a8 [2] fb b2 [2] e5 af [2] e7 ae [2] fc a8 [2] e0 af [2] fc 80 }

  condition:
    any of them
}