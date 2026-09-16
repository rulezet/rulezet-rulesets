rule TTP_XOR_QUAD_CurrentVersionRun_8093 {
  strings:
    $key_8093 = { d3 fc [2] f7 f2 [2] dc de [2] f2 fc [2] e6 e7 [2] e9 fd [2] f7 e0 [2] f5 e1 [2] ee e7 [2] f2 e0 [2] ee cf }

  condition:
    any of them
}