rule TTP_XOR_MULT_DOSStub_f692 {
  strings:
    $key_f692 = { a2 fa [2] d6 e2 [2] 91 e0 [2] d6 f1 [2] 98 fd [2] 94 f7 [2] 83 fc [2] 98 b2 [2] a5 }

  condition:
    any of them
}