rule TTP_XOR_MULT_DOSStub_add8 {
  strings:
    $key_add8 = { f9 b0 [2] 8d a8 [2] ca aa [2] 8d bb [2] c3 b7 [2] cf bd [2] d8 b6 [2] c3 f8 [2] fe }

  condition:
    any of them
}