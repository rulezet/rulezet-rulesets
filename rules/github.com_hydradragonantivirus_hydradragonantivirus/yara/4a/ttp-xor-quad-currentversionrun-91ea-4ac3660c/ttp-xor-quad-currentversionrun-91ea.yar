rule TTP_XOR_QUAD_CurrentVersionRun_91ea {
  strings:
    $key_91ea = { c2 85 [2] e6 8b [2] cd a7 [2] e3 85 [2] f7 9e [2] f8 84 [2] e6 99 [2] e4 98 [2] ff 9e [2] e3 99 [2] ff b6 }

  condition:
    any of them
}