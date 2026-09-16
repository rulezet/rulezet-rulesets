rule TTP_XOR_QUAD_CurrentVersionRun_95fc {
  strings:
    $key_95fc = { c6 93 [2] e2 9d [2] c9 b1 [2] e7 93 [2] f3 88 [2] fc 92 [2] e2 8f [2] e0 8e [2] fb 88 [2] e7 8f [2] fb a0 }

  condition:
    any of them
}