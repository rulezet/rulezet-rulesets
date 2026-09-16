rule TTP_XOR_QUAD_CurrentVersionRun_93c5 {
  strings:
    $key_93c5 = { c0 aa [2] e4 a4 [2] cf 88 [2] e1 aa [2] f5 b1 [2] fa ab [2] e4 b6 [2] e6 b7 [2] fd b1 [2] e1 b6 [2] fd 99 }

  condition:
    any of them
}