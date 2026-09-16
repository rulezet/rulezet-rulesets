rule TTP_XOR_QUAD_CurrentVersionRun_8431 {
  strings:
    $key_8431 = { d7 5e [2] f3 50 [2] d8 7c [2] f6 5e [2] e2 45 [2] ed 5f [2] f3 42 [2] f1 43 [2] ea 45 [2] f6 42 [2] ea 6d }

  condition:
    any of them
}