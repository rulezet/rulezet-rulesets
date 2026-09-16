rule TTP_XOR_MULT_DOSStub_2991 {
  strings:
    $key_2991 = { 7d f9 [2] 09 e1 [2] 4e e3 [2] 09 f2 [2] 47 fe [2] 4b f4 [2] 5c ff [2] 47 b1 [2] 7a }

  condition:
    any of them
}