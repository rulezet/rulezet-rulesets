rule TTP_XOR_MULT_DOSStub_e557 {
  strings:
    $key_e557 = { b1 3f [2] c5 27 [2] 82 25 [2] c5 34 [2] 8b 38 [2] 87 32 [2] 90 39 [2] 8b 77 [2] b6 }

  condition:
    any of them
}