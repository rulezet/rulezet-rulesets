rule TTP_XOR_QUAD_CurrentVersionRun_923f {
  strings:
    $key_923f = { c1 50 [2] e5 5e [2] ce 72 [2] e0 50 [2] f4 4b [2] fb 51 [2] e5 4c [2] e7 4d [2] fc 4b [2] e0 4c [2] fc 63 }

  condition:
    any of them
}