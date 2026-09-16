rule TTP_XOR_QUAD_CurrentVersionRun_8530 {
  strings:
    $key_8530 = { d6 5f [2] f2 51 [2] d9 7d [2] f7 5f [2] e3 44 [2] ec 5e [2] f2 43 [2] f0 42 [2] eb 44 [2] f7 43 [2] eb 6c }

  condition:
    any of them
}