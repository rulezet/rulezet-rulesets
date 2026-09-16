rule TTP_XOR_QUAD_CurrentVersionRun_e4c5 {
  strings:
    $key_e4c5 = { b7 aa [2] 93 a4 [2] b8 88 [2] 96 aa [2] 82 b1 [2] 8d ab [2] 93 b6 [2] 91 b7 [2] 8a b1 [2] 96 b6 [2] 8a 99 }

  condition:
    any of them
}