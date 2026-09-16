rule TTP_XOR_MULT_DOSStub_302a {
  strings:
    $key_302a = { 64 42 [2] 10 5a [2] 57 58 [2] 10 49 [2] 5e 45 [2] 52 4f [2] 45 44 [2] 5e 0a [2] 63 }

  condition:
    any of them
}