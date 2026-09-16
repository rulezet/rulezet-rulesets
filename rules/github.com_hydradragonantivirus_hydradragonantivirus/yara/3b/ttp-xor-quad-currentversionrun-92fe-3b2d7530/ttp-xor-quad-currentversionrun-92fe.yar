rule TTP_XOR_QUAD_CurrentVersionRun_92fe {
  strings:
    $key_92fe = { c1 91 [2] e5 9f [2] ce b3 [2] e0 91 [2] f4 8a [2] fb 90 [2] e5 8d [2] e7 8c [2] fc 8a [2] e0 8d [2] fc a2 }

  condition:
    any of them
}