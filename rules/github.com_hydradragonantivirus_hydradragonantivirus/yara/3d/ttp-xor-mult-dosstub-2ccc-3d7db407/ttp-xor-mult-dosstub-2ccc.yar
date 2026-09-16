rule TTP_XOR_MULT_DOSStub_2ccc {
  strings:
    $key_2ccc = { 78 a4 [2] 0c bc [2] 4b be [2] 0c af [2] 42 a3 [2] 4e a9 [2] 59 a2 [2] 42 ec [2] 7f }

  condition:
    any of them
}