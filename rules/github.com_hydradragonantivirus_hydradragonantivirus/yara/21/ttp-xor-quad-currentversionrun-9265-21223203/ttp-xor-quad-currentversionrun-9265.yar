rule TTP_XOR_QUAD_CurrentVersionRun_9265 {
  strings:
    $key_9265 = { c1 0a [2] e5 04 [2] ce 28 [2] e0 0a [2] f4 11 [2] fb 0b [2] e5 16 [2] e7 17 [2] fc 11 [2] e0 16 [2] fc 39 }

  condition:
    any of them
}