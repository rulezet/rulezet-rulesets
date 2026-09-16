rule TTP_XOR_QUAD_CurrentVersionRun_95e3 {
  strings:
    $key_95e3 = { c6 8c [2] e2 82 [2] c9 ae [2] e7 8c [2] f3 97 [2] fc 8d [2] e2 90 [2] e0 91 [2] fb 97 [2] e7 90 [2] fb bf }

  condition:
    any of them
}