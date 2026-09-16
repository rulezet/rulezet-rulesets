rule TTP_XOR_MULT_DOSStub_212a {
  strings:
    $key_212a = { 75 42 [2] 01 5a [2] 46 58 [2] 01 49 [2] 4f 45 [2] 43 4f [2] 54 44 [2] 4f 0a [2] 72 }

  condition:
    any of them
}