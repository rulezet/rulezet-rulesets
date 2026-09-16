rule TTP_XOR_QUAD_CurrentVersionRun_93c4 {
  strings:
    $key_93c4 = { c0 ab [2] e4 a5 [2] cf 89 [2] e1 ab [2] f5 b0 [2] fa aa [2] e4 b7 [2] e6 b6 [2] fd b0 [2] e1 b7 [2] fd 98 }

  condition:
    any of them
}