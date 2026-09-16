rule TTP_XOR_QUAD_CurrentVersionRun_840c {
  strings:
    $key_840c = { d7 63 [2] f3 6d [2] d8 41 [2] f6 63 [2] e2 78 [2] ed 62 [2] f3 7f [2] f1 7e [2] ea 78 [2] f6 7f [2] ea 50 }

  condition:
    any of them
}