rule TTP_XOR_QUAD_CurrentVersionRun_97c2 {
  strings:
    $key_97c2 = { c4 ad [2] e0 a3 [2] cb 8f [2] e5 ad [2] f1 b6 [2] fe ac [2] e0 b1 [2] e2 b0 [2] f9 b6 [2] e5 b1 [2] f9 9e }

  condition:
    any of them
}