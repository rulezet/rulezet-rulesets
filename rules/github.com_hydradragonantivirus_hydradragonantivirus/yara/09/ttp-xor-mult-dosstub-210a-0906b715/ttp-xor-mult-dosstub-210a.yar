rule TTP_XOR_MULT_DOSStub_210a {
  strings:
    $key_210a = { 75 62 [2] 01 7a [2] 46 78 [2] 01 69 [2] 4f 65 [2] 43 6f [2] 54 64 [2] 4f 2a [2] 72 }

  condition:
    any of them
}