rule TTP_XOR_MULT_DOSStub_203a {
  strings:
    $key_203a = { 74 52 [2] 00 4a [2] 47 48 [2] 00 59 [2] 4e 55 [2] 42 5f [2] 55 54 [2] 4e 1a [2] 73 }

  condition:
    any of them
}