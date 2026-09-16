rule TTP_XOR_QUAD_CurrentVersionRun_843d {
  strings:
    $key_843d = { d7 52 [2] f3 5c [2] d8 70 [2] f6 52 [2] e2 49 [2] ed 53 [2] f3 4e [2] f1 4f [2] ea 49 [2] f6 4e [2] ea 61 }

  condition:
    any of them
}