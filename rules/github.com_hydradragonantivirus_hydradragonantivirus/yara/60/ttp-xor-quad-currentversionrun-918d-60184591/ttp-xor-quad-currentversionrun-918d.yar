rule TTP_XOR_QUAD_CurrentVersionRun_918d {
  strings:
    $key_918d = { c2 e2 [2] e6 ec [2] cd c0 [2] e3 e2 [2] f7 f9 [2] f8 e3 [2] e6 fe [2] e4 ff [2] ff f9 [2] e3 fe [2] ff d1 }

  condition:
    any of them
}