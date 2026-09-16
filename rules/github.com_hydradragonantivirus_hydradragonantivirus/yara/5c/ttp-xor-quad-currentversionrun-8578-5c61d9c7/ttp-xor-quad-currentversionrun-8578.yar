rule TTP_XOR_QUAD_CurrentVersionRun_8578 {
  strings:
    $key_8578 = { d6 17 [2] f2 19 [2] d9 35 [2] f7 17 [2] e3 0c [2] ec 16 [2] f2 0b [2] f0 0a [2] eb 0c [2] f7 0b [2] eb 24 }

  condition:
    any of them
}