rule TTP_XOR_MULT_DOSStub_592a {
  strings:
    $key_592a = { 0d 42 [2] 79 5a [2] 3e 58 [2] 79 49 [2] 37 45 [2] 3b 4f [2] 2c 44 [2] 37 0a [2] 0a }

  condition:
    any of them
}