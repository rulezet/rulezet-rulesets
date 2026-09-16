rule TTP_XOR_MULT_DOSStub_7fcc {
  strings:
    $key_7fcc = { 2b a4 [2] 5f bc [2] 18 be [2] 5f af [2] 11 a3 [2] 1d a9 [2] 0a a2 [2] 11 ec [2] 2c }

  condition:
    any of them
}