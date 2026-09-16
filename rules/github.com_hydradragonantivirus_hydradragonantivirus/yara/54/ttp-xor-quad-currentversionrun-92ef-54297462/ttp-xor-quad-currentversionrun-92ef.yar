rule TTP_XOR_QUAD_CurrentVersionRun_92ef {
  strings:
    $key_92ef = { c1 80 [2] e5 8e [2] ce a2 [2] e0 80 [2] f4 9b [2] fb 81 [2] e5 9c [2] e7 9d [2] fc 9b [2] e0 9c [2] fc b3 }

  condition:
    any of them
}