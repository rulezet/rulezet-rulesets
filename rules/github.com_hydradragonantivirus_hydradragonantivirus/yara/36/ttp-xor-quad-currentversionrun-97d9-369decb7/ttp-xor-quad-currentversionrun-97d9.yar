rule TTP_XOR_QUAD_CurrentVersionRun_97d9 {
  strings:
    $key_97d9 = { c4 b6 [2] e0 b8 [2] cb 94 [2] e5 b6 [2] f1 ad [2] fe b7 [2] e0 aa [2] e2 ab [2] f9 ad [2] e5 aa [2] f9 85 }

  condition:
    any of them
}