rule TTP_XOR_QUAD_CurrentVersionRun_91f7 {
  strings:
    $key_91f7 = { c2 98 [2] e6 96 [2] cd ba [2] e3 98 [2] f7 83 [2] f8 99 [2] e6 84 [2] e4 85 [2] ff 83 [2] e3 84 [2] ff ab }

  condition:
    any of them
}