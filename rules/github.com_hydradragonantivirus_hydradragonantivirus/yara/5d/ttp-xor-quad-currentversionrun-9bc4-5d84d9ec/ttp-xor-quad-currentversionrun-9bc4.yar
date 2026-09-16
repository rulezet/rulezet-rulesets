rule TTP_XOR_QUAD_CurrentVersionRun_9bc4 {
  strings:
    $key_9bc4 = { c8 ab [2] ec a5 [2] c7 89 [2] e9 ab [2] fd b0 [2] f2 aa [2] ec b7 [2] ee b6 [2] f5 b0 [2] e9 b7 [2] f5 98 }

  condition:
    any of them
}