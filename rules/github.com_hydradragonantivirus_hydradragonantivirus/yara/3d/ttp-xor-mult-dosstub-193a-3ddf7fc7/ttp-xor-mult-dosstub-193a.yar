rule TTP_XOR_MULT_DOSStub_193a {
  strings:
    $key_193a = { 4d 52 [2] 39 4a [2] 7e 48 [2] 39 59 [2] 77 55 [2] 7b 5f [2] 6c 54 [2] 77 1a [2] 4a }

  condition:
    any of them
}