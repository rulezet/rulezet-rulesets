rule TTP_XOR_QUAD_CurrentVersionRun_833a {
  strings:
    $key_833a = { d0 55 [2] f4 5b [2] df 77 [2] f1 55 [2] e5 4e [2] ea 54 [2] f4 49 [2] f6 48 [2] ed 4e [2] f1 49 [2] ed 66 }

  condition:
    any of them
}