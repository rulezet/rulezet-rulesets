rule TTP_XOR_MULT_DOSStub_196a {
  strings:
    $key_196a = { 4d 02 [2] 39 1a [2] 7e 18 [2] 39 09 [2] 77 05 [2] 7b 0f [2] 6c 04 [2] 77 4a [2] 4a }

  condition:
    any of them
}