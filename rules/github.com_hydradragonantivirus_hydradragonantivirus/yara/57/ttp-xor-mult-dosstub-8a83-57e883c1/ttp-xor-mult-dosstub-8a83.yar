rule TTP_XOR_MULT_DOSStub_8a83 {
  strings:
    $key_8a83 = { de eb [2] aa f3 [2] ed f1 [2] aa e0 [2] e4 ec [2] e8 e6 [2] ff ed [2] e4 a3 [2] d9 }

  condition:
    any of them
}