rule TTP_XOR_QUAD_CurrentVersionRun_950d {
  strings:
    $key_950d = { c6 62 [2] e2 6c [2] c9 40 [2] e7 62 [2] f3 79 [2] fc 63 [2] e2 7e [2] e0 7f [2] fb 79 [2] e7 7e [2] fb 51 }

  condition:
    any of them
}