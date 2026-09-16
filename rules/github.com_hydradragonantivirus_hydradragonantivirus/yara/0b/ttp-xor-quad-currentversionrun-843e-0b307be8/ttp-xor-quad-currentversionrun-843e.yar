rule TTP_XOR_QUAD_CurrentVersionRun_843e {
  strings:
    $key_843e = { d7 51 [2] f3 5f [2] d8 73 [2] f6 51 [2] e2 4a [2] ed 50 [2] f3 4d [2] f1 4c [2] ea 4a [2] f6 4d [2] ea 62 }

  condition:
    any of them
}