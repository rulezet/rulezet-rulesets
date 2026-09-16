rule TTP_XOR_QUAD_CurrentVersionRun_9dc2 {
  strings:
    $key_9dc2 = { ce ad [2] ea a3 [2] c1 8f [2] ef ad [2] fb b6 [2] f4 ac [2] ea b1 [2] e8 b0 [2] f3 b6 [2] ef b1 [2] f3 9e }

  condition:
    any of them
}