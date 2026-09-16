rule TTP_XOR_QUAD_CurrentVersionRun_9216 {
  strings:
    $key_9216 = { c1 79 [2] e5 77 [2] ce 5b [2] e0 79 [2] f4 62 [2] fb 78 [2] e5 65 [2] e7 64 [2] fc 62 [2] e0 65 [2] fc 4a }

  condition:
    any of them
}