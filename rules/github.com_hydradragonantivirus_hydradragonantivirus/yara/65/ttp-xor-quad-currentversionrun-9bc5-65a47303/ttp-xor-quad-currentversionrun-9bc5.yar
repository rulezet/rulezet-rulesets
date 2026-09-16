rule TTP_XOR_QUAD_CurrentVersionRun_9bc5 {
  strings:
    $key_9bc5 = { c8 aa [2] ec a4 [2] c7 88 [2] e9 aa [2] fd b1 [2] f2 ab [2] ec b6 [2] ee b7 [2] f5 b1 [2] e9 b6 [2] f5 99 }

  condition:
    any of them
}