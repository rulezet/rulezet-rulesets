rule TTP_XOR_QUAD_CurrentVersionRun_95c5 {
  strings:
    $key_95c5 = { c6 aa [2] e2 a4 [2] c9 88 [2] e7 aa [2] f3 b1 [2] fc ab [2] e2 b6 [2] e0 b7 [2] fb b1 [2] e7 b6 [2] fb 99 }

  condition:
    any of them
}