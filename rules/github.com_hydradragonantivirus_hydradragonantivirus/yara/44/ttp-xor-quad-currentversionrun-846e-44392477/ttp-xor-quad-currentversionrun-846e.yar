rule TTP_XOR_QUAD_CurrentVersionRun_846e {
  strings:
    $key_846e = { d7 01 [2] f3 0f [2] d8 23 [2] f6 01 [2] e2 1a [2] ed 00 [2] f3 1d [2] f1 1c [2] ea 1a [2] f6 1d [2] ea 32 }

  condition:
    any of them
}