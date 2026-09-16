rule TTP_XOR_MULT_DOSStub_1ccc {
  strings:
    $key_1ccc = { 48 a4 [2] 3c bc [2] 7b be [2] 3c af [2] 72 a3 [2] 7e a9 [2] 69 a2 [2] 72 ec [2] 4f }

  condition:
    any of them
}