rule TTP_XOR_QUAD_CurrentVersionRun_9dc5 {
  strings:
    $key_9dc5 = { ce aa [2] ea a4 [2] c1 88 [2] ef aa [2] fb b1 [2] f4 ab [2] ea b6 [2] e8 b7 [2] f3 b1 [2] ef b6 [2] f3 99 }

  condition:
    any of them
}