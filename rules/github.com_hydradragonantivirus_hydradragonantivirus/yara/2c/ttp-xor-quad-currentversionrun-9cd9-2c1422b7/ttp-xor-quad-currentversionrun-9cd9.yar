rule TTP_XOR_QUAD_CurrentVersionRun_9cd9 {
  strings:
    $key_9cd9 = { cf b6 [2] eb b8 [2] c0 94 [2] ee b6 [2] fa ad [2] f5 b7 [2] eb aa [2] e9 ab [2] f2 ad [2] ee aa [2] f2 85 }

  condition:
    any of them
}