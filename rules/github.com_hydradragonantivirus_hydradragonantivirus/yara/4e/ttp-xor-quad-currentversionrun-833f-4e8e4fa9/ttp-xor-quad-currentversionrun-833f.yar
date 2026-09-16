rule TTP_XOR_QUAD_CurrentVersionRun_833f {
  strings:
    $key_833f = { d0 50 [2] f4 5e [2] df 72 [2] f1 50 [2] e5 4b [2] ea 51 [2] f4 4c [2] f6 4d [2] ed 4b [2] f1 4c [2] ed 63 }

  condition:
    any of them
}