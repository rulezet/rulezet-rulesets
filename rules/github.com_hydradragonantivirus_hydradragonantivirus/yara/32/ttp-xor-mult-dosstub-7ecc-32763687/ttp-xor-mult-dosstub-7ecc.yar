rule TTP_XOR_MULT_DOSStub_7ecc {
  strings:
    $key_7ecc = { 2a a4 [2] 5e bc [2] 19 be [2] 5e af [2] 10 a3 [2] 1c a9 [2] 0b a2 [2] 10 ec [2] 2d }

  condition:
    any of them
}