rule TTP_XOR_MULT_DOSStub_fad9 {
  strings:
    $key_fad9 = { ae b1 [2] da a9 [2] 9d ab [2] da ba [2] 94 b6 [2] 98 bc [2] 8f b7 [2] 94 f9 [2] a9 }

  condition:
    any of them
}