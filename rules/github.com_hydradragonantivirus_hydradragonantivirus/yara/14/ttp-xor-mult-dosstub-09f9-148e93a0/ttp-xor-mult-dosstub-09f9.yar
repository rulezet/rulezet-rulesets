rule TTP_XOR_MULT_DOSStub_09f9 {
  strings:
    $key_09f9 = { 5d 91 [2] 29 89 [2] 6e 8b [2] 29 9a [2] 67 96 [2] 6b 9c [2] 7c 97 [2] 67 d9 [2] 5a }

  condition:
    any of them
}