rule TTP_XOR_MULT_DOSStub_49f9 {
  strings:
    $key_49f9 = { 1d 91 [2] 69 89 [2] 2e 8b [2] 69 9a [2] 27 96 [2] 2b 9c [2] 3c 97 [2] 27 d9 [2] 1a }

  condition:
    any of them
}