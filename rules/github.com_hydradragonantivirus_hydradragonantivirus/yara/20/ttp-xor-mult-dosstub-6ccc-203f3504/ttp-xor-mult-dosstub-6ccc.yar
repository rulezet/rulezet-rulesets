rule TTP_XOR_MULT_DOSStub_6ccc {
  strings:
    $key_6ccc = { 38 a4 [2] 4c bc [2] 0b be [2] 4c af [2] 02 a3 [2] 0e a9 [2] 19 a2 [2] 02 ec [2] 3f }

  condition:
    any of them
}