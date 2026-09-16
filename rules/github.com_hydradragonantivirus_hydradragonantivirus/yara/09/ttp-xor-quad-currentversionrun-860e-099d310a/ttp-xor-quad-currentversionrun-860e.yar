rule TTP_XOR_QUAD_CurrentVersionRun_860e {
  strings:
    $key_860e = { d5 61 [2] f1 6f [2] da 43 [2] f4 61 [2] e0 7a [2] ef 60 [2] f1 7d [2] f3 7c [2] e8 7a [2] f4 7d [2] e8 52 }

  condition:
    any of them
}