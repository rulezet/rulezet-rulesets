rule TTP_XOR_QUAD_CurrentVersionRun_9193 {
  strings:
    $key_9193 = { c2 fc [2] e6 f2 [2] cd de [2] e3 fc [2] f7 e7 [2] f8 fd [2] e6 e0 [2] e4 e1 [2] ff e7 [2] e3 e0 [2] ff cf }

  condition:
    any of them
}