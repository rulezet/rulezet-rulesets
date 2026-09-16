rule TTP_XOR_MULT_DOSStub_fac2 {
  strings:
    $key_fac2 = { ae aa [2] da b2 [2] 9d b0 [2] da a1 [2] 94 ad [2] 98 a7 [2] 8f ac [2] 94 e2 [2] a9 }

  condition:
    any of them
}