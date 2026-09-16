rule TTP_XOR_QUAD_CurrentVersionRun_84fe {
  strings:
    $key_84fe = { d7 91 [2] f3 9f [2] d8 b3 [2] f6 91 [2] e2 8a [2] ed 90 [2] f3 8d [2] f1 8c [2] ea 8a [2] f6 8d [2] ea a2 }

  condition:
    any of them
}