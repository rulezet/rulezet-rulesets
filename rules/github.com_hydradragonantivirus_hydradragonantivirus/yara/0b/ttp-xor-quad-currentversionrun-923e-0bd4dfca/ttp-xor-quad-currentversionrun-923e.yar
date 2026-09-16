rule TTP_XOR_QUAD_CurrentVersionRun_923e {
  strings:
    $key_923e = { c1 51 [2] e5 5f [2] ce 73 [2] e0 51 [2] f4 4a [2] fb 50 [2] e5 4d [2] e7 4c [2] fc 4a [2] e0 4d [2] fc 62 }

  condition:
    any of them
}