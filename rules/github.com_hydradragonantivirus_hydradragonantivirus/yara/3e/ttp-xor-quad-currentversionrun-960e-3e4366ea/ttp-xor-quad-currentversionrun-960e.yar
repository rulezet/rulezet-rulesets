rule TTP_XOR_QUAD_CurrentVersionRun_960e {
  strings:
    $key_960e = { c5 61 [2] e1 6f [2] ca 43 [2] e4 61 [2] f0 7a [2] ff 60 [2] e1 7d [2] e3 7c [2] f8 7a [2] e4 7d [2] f8 52 }

  condition:
    any of them
}