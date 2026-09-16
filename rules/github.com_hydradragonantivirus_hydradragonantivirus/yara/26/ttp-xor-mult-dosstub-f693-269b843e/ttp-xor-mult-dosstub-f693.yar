rule TTP_XOR_MULT_DOSStub_f693 {
  strings:
    $key_f693 = { a2 fb [2] d6 e3 [2] 91 e1 [2] d6 f0 [2] 98 fc [2] 94 f6 [2] 83 fd [2] 98 b3 [2] a5 }

  condition:
    any of them
}