rule TTP_XOR_MULT_DOSStub_0fcc {
  strings:
    $key_0fcc = { 5b a4 [2] 2f bc [2] 68 be [2] 2f af [2] 61 a3 [2] 6d a9 [2] 7a a2 [2] 61 ec [2] 5c }

  condition:
    any of them
}