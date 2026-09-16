rule TTP_XOR_MULT_DOSStub_2dcb {
  strings:
    $key_2dcb = { 79 a3 [2] 0d bb [2] 4a b9 [2] 0d a8 [2] 43 a4 [2] 4f ae [2] 58 a5 [2] 43 eb [2] 7e }

  condition:
    any of them
}