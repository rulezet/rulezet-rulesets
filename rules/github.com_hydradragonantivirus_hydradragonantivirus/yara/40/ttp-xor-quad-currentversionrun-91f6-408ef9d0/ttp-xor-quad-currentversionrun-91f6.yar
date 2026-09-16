rule TTP_XOR_QUAD_CurrentVersionRun_91f6 {
  strings:
    $key_91f6 = { c2 99 [2] e6 97 [2] cd bb [2] e3 99 [2] f7 82 [2] f8 98 [2] e6 85 [2] e4 84 [2] ff 82 [2] e3 85 [2] ff aa }

  condition:
    any of them
}