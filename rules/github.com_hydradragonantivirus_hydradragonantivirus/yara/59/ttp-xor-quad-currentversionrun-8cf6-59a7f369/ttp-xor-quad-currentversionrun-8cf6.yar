rule TTP_XOR_QUAD_CurrentVersionRun_8cf6 {
  strings:
    $key_8cf6 = { df 99 [2] fb 97 [2] d0 bb [2] fe 99 [2] ea 82 [2] e5 98 [2] fb 85 [2] f9 84 [2] e2 82 [2] fe 85 [2] e2 aa }

  condition:
    any of them
}