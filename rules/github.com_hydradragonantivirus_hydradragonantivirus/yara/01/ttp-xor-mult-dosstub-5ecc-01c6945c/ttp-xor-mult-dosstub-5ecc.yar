rule TTP_XOR_MULT_DOSStub_5ecc {
  strings:
    $key_5ecc = { 0a a4 [2] 7e bc [2] 39 be [2] 7e af [2] 30 a3 [2] 3c a9 [2] 2b a2 [2] 30 ec [2] 0d }

  condition:
    any of them
}