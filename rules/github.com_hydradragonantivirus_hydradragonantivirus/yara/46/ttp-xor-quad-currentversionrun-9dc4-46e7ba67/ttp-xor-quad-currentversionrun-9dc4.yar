rule TTP_XOR_QUAD_CurrentVersionRun_9dc4 {
  strings:
    $key_9dc4 = { ce ab [2] ea a5 [2] c1 89 [2] ef ab [2] fb b0 [2] f4 aa [2] ea b7 [2] e8 b6 [2] f3 b0 [2] ef b7 [2] f3 98 }

  condition:
    any of them
}