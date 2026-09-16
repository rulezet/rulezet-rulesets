rule TTP_XOR_MULT_DOSStub_219a {
  strings:
    $key_219a = { 75 f2 [2] 01 ea [2] 46 e8 [2] 01 f9 [2] 4f f5 [2] 43 ff [2] 54 f4 [2] 4f ba [2] 72 }

  condition:
    any of them
}