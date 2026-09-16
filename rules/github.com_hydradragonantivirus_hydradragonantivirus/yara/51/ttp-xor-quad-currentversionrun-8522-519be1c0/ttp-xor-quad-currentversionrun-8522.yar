rule TTP_XOR_QUAD_CurrentVersionRun_8522 {
  strings:
    $key_8522 = { d6 4d [2] f2 43 [2] d9 6f [2] f7 4d [2] e3 56 [2] ec 4c [2] f2 51 [2] f0 50 [2] eb 56 [2] f7 51 [2] eb 7e }

  condition:
    any of them
}