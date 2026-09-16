rule TTP_XOR_QUAD_CurrentVersionRun_9b32 {
  strings:
    $key_9b32 = { c8 5d [2] ec 53 [2] c7 7f [2] e9 5d [2] fd 46 [2] f2 5c [2] ec 41 [2] ee 40 [2] f5 46 [2] e9 41 [2] f5 6e }

  condition:
    any of them
}