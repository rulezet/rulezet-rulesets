rule TTP_XOR_QUAD_CurrentVersionRun_8ec5 {
  strings:
    $key_8ec5 = { dd aa [2] f9 a4 [2] d2 88 [2] fc aa [2] e8 b1 [2] e7 ab [2] f9 b6 [2] fb b7 [2] e0 b1 [2] fc b6 [2] e0 99 }

  condition:
    any of them
}