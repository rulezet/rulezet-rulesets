rule TTP_XOR_QUAD_CurrentVersionRun_953b {
  strings:
    $key_953b = { c6 54 [2] e2 5a [2] c9 76 [2] e7 54 [2] f3 4f [2] fc 55 [2] e2 48 [2] e0 49 [2] fb 4f [2] e7 48 [2] fb 67 }

  condition:
    any of them
}