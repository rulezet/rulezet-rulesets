rule TTP_XOR_QUAD_CurrentVersionRun_833d {
  strings:
    $key_833d = { d0 52 [2] f4 5c [2] df 70 [2] f1 52 [2] e5 49 [2] ea 53 [2] f4 4e [2] f6 4f [2] ed 49 [2] f1 4e [2] ed 61 }

  condition:
    any of them
}