rule TTP_XOR_QUAD_CurrentVersionRun_852d {
  strings:
    $key_852d = { d6 42 [2] f2 4c [2] d9 60 [2] f7 42 [2] e3 59 [2] ec 43 [2] f2 5e [2] f0 5f [2] eb 59 [2] f7 5e [2] eb 71 }

  condition:
    any of them
}