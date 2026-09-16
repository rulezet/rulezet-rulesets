rule TTP_XOR_MULT_DOSStub_7dcc {
  strings:
    $key_7dcc = { 29 a4 [2] 5d bc [2] 1a be [2] 5d af [2] 13 a3 [2] 1f a9 [2] 08 a2 [2] 13 ec [2] 2e }

  condition:
    any of them
}