rule TTP_XOR_QUAD_CurrentVersionRun_91ef {
  strings:
    $key_91ef = { c2 80 [2] e6 8e [2] cd a2 [2] e3 80 [2] f7 9b [2] f8 81 [2] e6 9c [2] e4 9d [2] ff 9b [2] e3 9c [2] ff b3 }

  condition:
    any of them
}