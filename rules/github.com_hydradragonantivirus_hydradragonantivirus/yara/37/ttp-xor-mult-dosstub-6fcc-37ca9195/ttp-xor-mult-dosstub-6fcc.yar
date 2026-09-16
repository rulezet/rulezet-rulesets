rule TTP_XOR_MULT_DOSStub_6fcc {
  strings:
    $key_6fcc = { 3b a4 [2] 4f bc [2] 08 be [2] 4f af [2] 01 a3 [2] 0d a9 [2] 1a a2 [2] 01 ec [2] 3c }

  condition:
    any of them
}