rule TTP_XOR_MULT_DOSStub_597d {
  strings:
    $key_597d = { 0d 15 [2] 79 0d [2] 3e 0f [2] 79 1e [2] 37 12 [2] 3b 18 [2] 2c 13 [2] 37 5d [2] 0a }

  condition:
    any of them
}