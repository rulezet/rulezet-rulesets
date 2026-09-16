rule TTP_XOR_QUAD_CurrentVersionRun_9217 {
  strings:
    $key_9217 = { c1 78 [2] e5 76 [2] ce 5a [2] e0 78 [2] f4 63 [2] fb 79 [2] e5 64 [2] e7 65 [2] fc 63 [2] e0 64 [2] fc 4b }

  condition:
    any of them
}