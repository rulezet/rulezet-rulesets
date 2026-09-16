rule TTP_XOR_QUAD_CurrentVersionRun_8520 {
  strings:
    $key_8520 = { d6 4f [2] f2 41 [2] d9 6d [2] f7 4f [2] e3 54 [2] ec 4e [2] f2 53 [2] f0 52 [2] eb 54 [2] f7 53 [2] eb 7c }

  condition:
    any of them
}