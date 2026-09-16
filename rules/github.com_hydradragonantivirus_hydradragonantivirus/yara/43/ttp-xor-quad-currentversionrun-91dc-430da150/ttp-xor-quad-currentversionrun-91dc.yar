rule TTP_XOR_QUAD_CurrentVersionRun_91dc {
  strings:
    $key_91dc = { c2 b3 [2] e6 bd [2] cd 91 [2] e3 b3 [2] f7 a8 [2] f8 b2 [2] e6 af [2] e4 ae [2] ff a8 [2] e3 af [2] ff 80 }

  condition:
    any of them
}