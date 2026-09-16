rule TTP_XOR_QUAD_CurrentVersionRun_9211 {
  strings:
    $key_9211 = { c1 7e [2] e5 70 [2] ce 5c [2] e0 7e [2] f4 65 [2] fb 7f [2] e5 62 [2] e7 63 [2] fc 65 [2] e0 62 [2] fc 4d }

  condition:
    any of them
}