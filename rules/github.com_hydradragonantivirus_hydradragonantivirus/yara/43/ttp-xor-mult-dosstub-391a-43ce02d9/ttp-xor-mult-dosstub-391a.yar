rule TTP_XOR_MULT_DOSStub_391a {
  strings:
    $key_391a = { 6d 72 [2] 19 6a [2] 5e 68 [2] 19 79 [2] 57 75 [2] 5b 7f [2] 4c 74 [2] 57 3a [2] 6a }

  condition:
    any of them
}