rule TTP_XOR_QUAD_CurrentVersionRun_9227 {
  strings:
    $key_9227 = { c1 48 [2] e5 46 [2] ce 6a [2] e0 48 [2] f4 53 [2] fb 49 [2] e5 54 [2] e7 55 [2] fc 53 [2] e0 54 [2] fc 7b }

  condition:
    any of them
}