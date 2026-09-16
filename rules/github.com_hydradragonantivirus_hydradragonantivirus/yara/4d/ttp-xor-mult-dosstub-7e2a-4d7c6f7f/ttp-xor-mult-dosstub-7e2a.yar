rule TTP_XOR_MULT_DOSStub_7e2a {
  strings:
    $key_7e2a = { 2a 42 [2] 5e 5a [2] 19 58 [2] 5e 49 [2] 10 45 [2] 1c 4f [2] 0b 44 [2] 10 0a [2] 2d }

  condition:
    any of them
}