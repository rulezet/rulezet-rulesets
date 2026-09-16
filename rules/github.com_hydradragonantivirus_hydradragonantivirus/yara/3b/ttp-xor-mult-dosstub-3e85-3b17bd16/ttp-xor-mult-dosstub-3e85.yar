rule TTP_XOR_MULT_DOSStub_3e85 {
  strings:
    $key_3e85 = { 6a ed [2] 1e f5 [2] 59 f7 [2] 1e e6 [2] 50 ea [2] 5c e0 [2] 4b eb [2] 50 a5 [2] 6d }

  condition:
    any of them
}