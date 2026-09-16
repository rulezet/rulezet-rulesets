rule TTP_XOR_QUAD_CurrentVersionRun_8ecf {
  strings:
    $key_8ecf = { dd a0 [2] f9 ae [2] d2 82 [2] fc a0 [2] e8 bb [2] e7 a1 [2] f9 bc [2] fb bd [2] e0 bb [2] fc bc [2] e0 93 }

  condition:
    any of them
}