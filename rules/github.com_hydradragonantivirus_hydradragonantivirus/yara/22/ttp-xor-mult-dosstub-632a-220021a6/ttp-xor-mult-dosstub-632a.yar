rule TTP_XOR_MULT_DOSStub_632a {
  strings:
    $key_632a = { 37 42 [2] 43 5a [2] 04 58 [2] 43 49 [2] 0d 45 [2] 01 4f [2] 16 44 [2] 0d 0a [2] 30 }

  condition:
    any of them
}