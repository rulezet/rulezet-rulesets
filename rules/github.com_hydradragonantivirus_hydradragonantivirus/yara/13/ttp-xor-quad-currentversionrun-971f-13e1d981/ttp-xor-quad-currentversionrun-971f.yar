rule TTP_XOR_QUAD_CurrentVersionRun_971f {
  strings:
    $key_971f = { c4 70 [2] e0 7e [2] cb 52 [2] e5 70 [2] f1 6b [2] fe 71 [2] e0 6c [2] e2 6d [2] f9 6b [2] e5 6c [2] f9 43 }

  condition:
    any of them
}