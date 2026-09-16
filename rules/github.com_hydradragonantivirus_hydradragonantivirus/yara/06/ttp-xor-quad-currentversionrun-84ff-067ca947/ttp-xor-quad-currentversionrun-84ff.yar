rule TTP_XOR_QUAD_CurrentVersionRun_84ff {
  strings:
    $key_84ff = { d7 90 [2] f3 9e [2] d8 b2 [2] f6 90 [2] e2 8b [2] ed 91 [2] f3 8c [2] f1 8d [2] ea 8b [2] f6 8c [2] ea a3 }

  condition:
    any of them
}