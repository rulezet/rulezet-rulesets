rule TTP_XOR_MULT_DOSStub_659a {
  strings:
    $key_659a = { 31 f2 [2] 45 ea [2] 02 e8 [2] 45 f9 [2] 0b f5 [2] 07 ff [2] 10 f4 [2] 0b ba [2] 36 }

  condition:
    any of them
}