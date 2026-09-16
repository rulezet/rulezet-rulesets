rule TTP_XOR_QUAD_CurrentVersionRun_91c2 {
  strings:
    $key_91c2 = { c2 ad [2] e6 a3 [2] cd 8f [2] e3 ad [2] f7 b6 [2] f8 ac [2] e6 b1 [2] e4 b0 [2] ff b6 [2] e3 b1 [2] ff 9e }

  condition:
    any of them
}