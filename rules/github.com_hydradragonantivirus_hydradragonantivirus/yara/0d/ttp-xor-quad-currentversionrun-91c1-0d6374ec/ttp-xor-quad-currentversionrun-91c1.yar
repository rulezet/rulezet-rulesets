rule TTP_XOR_QUAD_CurrentVersionRun_91c1 {
  strings:
    $key_91c1 = { c2 ae [2] e6 a0 [2] cd 8c [2] e3 ae [2] f7 b5 [2] f8 af [2] e6 b2 [2] e4 b3 [2] ff b5 [2] e3 b2 [2] ff 9d }

  condition:
    any of them
}