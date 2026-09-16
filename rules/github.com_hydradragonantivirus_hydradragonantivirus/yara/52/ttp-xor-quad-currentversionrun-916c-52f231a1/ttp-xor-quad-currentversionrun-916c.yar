rule TTP_XOR_QUAD_CurrentVersionRun_916c {
  strings:
    $key_916c = { c2 03 [2] e6 0d [2] cd 21 [2] e3 03 [2] f7 18 [2] f8 02 [2] e6 1f [2] e4 1e [2] ff 18 [2] e3 1f [2] ff 30 }

  condition:
    any of them
}