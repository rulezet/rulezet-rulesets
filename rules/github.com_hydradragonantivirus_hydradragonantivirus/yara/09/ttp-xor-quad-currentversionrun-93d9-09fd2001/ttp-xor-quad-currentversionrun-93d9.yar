rule TTP_XOR_QUAD_CurrentVersionRun_93d9 {
  strings:
    $key_93d9 = { c0 b6 [2] e4 b8 [2] cf 94 [2] e1 b6 [2] f5 ad [2] fa b7 [2] e4 aa [2] e6 ab [2] fd ad [2] e1 aa [2] fd 85 }

  condition:
    any of them
}