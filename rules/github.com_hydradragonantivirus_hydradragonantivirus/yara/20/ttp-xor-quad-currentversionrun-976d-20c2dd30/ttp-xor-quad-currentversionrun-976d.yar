rule TTP_XOR_QUAD_CurrentVersionRun_976d {
  strings:
    $key_976d = { c4 02 [2] e0 0c [2] cb 20 [2] e5 02 [2] f1 19 [2] fe 03 [2] e0 1e [2] e2 1f [2] f9 19 [2] e5 1e [2] f9 31 }

  condition:
    any of them
}