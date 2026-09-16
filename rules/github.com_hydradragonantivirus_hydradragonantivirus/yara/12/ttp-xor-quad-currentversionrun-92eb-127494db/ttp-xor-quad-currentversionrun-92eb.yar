rule TTP_XOR_QUAD_CurrentVersionRun_92eb {
  strings:
    $key_92eb = { c1 84 [2] e5 8a [2] ce a6 [2] e0 84 [2] f4 9f [2] fb 85 [2] e5 98 [2] e7 99 [2] fc 9f [2] e0 98 [2] fc b7 }

  condition:
    any of them
}