rule TTP_XOR_MULT_DOSStub_fad3 {
  strings:
    $key_fad3 = { ae bb [2] da a3 [2] 9d a1 [2] da b0 [2] 94 bc [2] 98 b6 [2] 8f bd [2] 94 f3 [2] a9 }

  condition:
    any of them
}