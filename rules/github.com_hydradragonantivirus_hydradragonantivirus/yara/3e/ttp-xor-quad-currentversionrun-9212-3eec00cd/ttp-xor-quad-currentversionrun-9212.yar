rule TTP_XOR_QUAD_CurrentVersionRun_9212 {
  strings:
    $key_9212 = { c1 7d [2] e5 73 [2] ce 5f [2] e0 7d [2] f4 66 [2] fb 7c [2] e5 61 [2] e7 60 [2] fc 66 [2] e0 61 [2] fc 4e }

  condition:
    any of them
}