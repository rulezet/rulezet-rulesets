rule TTP_XOR_MULT_DOSStub_3ccc {
  strings:
    $key_3ccc = { 68 a4 [2] 1c bc [2] 5b be [2] 1c af [2] 52 a3 [2] 5e a9 [2] 49 a2 [2] 52 ec [2] 6f }

  condition:
    any of them
}