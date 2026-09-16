rule TTP_XOR_MULT_DOSStub_2f83 {
  strings:
    $key_2f83 = { 7b eb [2] 0f f3 [2] 48 f1 [2] 0f e0 [2] 41 ec [2] 4d e6 [2] 5a ed [2] 41 a3 [2] 7c }

  condition:
    any of them
}