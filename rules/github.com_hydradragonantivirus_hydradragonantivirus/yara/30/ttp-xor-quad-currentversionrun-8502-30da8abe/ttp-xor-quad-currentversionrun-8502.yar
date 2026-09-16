rule TTP_XOR_QUAD_CurrentVersionRun_8502 {
  strings:
    $key_8502 = { d6 6d [2] f2 63 [2] d9 4f [2] f7 6d [2] e3 76 [2] ec 6c [2] f2 71 [2] f0 70 [2] eb 76 [2] f7 71 [2] eb 5e }

  condition:
    any of them
}