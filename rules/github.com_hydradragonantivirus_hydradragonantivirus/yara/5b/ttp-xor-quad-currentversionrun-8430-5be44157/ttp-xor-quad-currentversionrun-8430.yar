rule TTP_XOR_QUAD_CurrentVersionRun_8430 {
  strings:
    $key_8430 = { d7 5f [2] f3 51 [2] d8 7d [2] f6 5f [2] e2 44 [2] ed 5e [2] f3 43 [2] f1 42 [2] ea 44 [2] f6 43 [2] ea 6c }

  condition:
    any of them
}