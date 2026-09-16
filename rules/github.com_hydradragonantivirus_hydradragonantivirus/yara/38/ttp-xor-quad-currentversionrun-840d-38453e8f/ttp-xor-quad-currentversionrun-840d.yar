rule TTP_XOR_QUAD_CurrentVersionRun_840d {
  strings:
    $key_840d = { d7 62 [2] f3 6c [2] d8 40 [2] f6 62 [2] e2 79 [2] ed 63 [2] f3 7e [2] f1 7f [2] ea 79 [2] f6 7e [2] ea 51 }

  condition:
    any of them
}