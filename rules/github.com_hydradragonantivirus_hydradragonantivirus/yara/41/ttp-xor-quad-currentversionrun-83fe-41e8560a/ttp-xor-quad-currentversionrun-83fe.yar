rule TTP_XOR_QUAD_CurrentVersionRun_83fe {
  strings:
    $key_83fe = { d0 91 [2] f4 9f [2] df b3 [2] f1 91 [2] e5 8a [2] ea 90 [2] f4 8d [2] f6 8c [2] ed 8a [2] f1 8d [2] ed a2 }

  condition:
    any of them
}