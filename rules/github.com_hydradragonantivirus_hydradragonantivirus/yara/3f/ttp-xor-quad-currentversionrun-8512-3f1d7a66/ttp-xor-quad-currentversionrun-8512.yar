rule TTP_XOR_QUAD_CurrentVersionRun_8512 {
  strings:
    $key_8512 = { d6 7d [2] f2 73 [2] d9 5f [2] f7 7d [2] e3 66 [2] ec 7c [2] f2 61 [2] f0 60 [2] eb 66 [2] f7 61 [2] eb 4e }

  condition:
    any of them
}