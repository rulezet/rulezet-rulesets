rule TTP_XOR_MULT_DOSStub_fad5 {
  strings:
    $key_fad5 = { ae bd [2] da a5 [2] 9d a7 [2] da b6 [2] 94 ba [2] 98 b0 [2] 8f bb [2] 94 f5 [2] a9 }

  condition:
    any of them
}