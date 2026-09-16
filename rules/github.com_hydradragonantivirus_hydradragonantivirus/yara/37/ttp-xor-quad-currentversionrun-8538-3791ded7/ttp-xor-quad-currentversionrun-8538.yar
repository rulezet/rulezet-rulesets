rule TTP_XOR_QUAD_CurrentVersionRun_8538 {
  strings:
    $key_8538 = { d6 57 [2] f2 59 [2] d9 75 [2] f7 57 [2] e3 4c [2] ec 56 [2] f2 4b [2] f0 4a [2] eb 4c [2] f7 4b [2] eb 64 }

  condition:
    any of them
}