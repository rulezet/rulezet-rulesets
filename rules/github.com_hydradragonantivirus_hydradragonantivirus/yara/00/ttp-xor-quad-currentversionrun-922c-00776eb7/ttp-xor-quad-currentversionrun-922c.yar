rule TTP_XOR_QUAD_CurrentVersionRun_922c {
  strings:
    $key_922c = { c1 43 [2] e5 4d [2] ce 61 [2] e0 43 [2] f4 58 [2] fb 42 [2] e5 5f [2] e7 5e [2] fc 58 [2] e0 5f [2] fc 70 }

  condition:
    any of them
}