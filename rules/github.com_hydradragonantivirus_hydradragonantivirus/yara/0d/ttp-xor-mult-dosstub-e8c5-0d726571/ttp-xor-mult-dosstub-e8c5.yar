rule TTP_XOR_MULT_DOSStub_e8c5 {
  strings:
    $key_e8c5 = { bc ad [2] c8 b5 [2] 8f b7 [2] c8 a6 [2] 86 aa [2] 8a a0 [2] 9d ab [2] 86 e5 [2] bb }

  condition:
    any of them
}