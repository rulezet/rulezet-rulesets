rule TTP_XOR_MULT_DOSStub_193f {
  strings:
    $key_193f = { 4d 57 [2] 39 4f [2] 7e 4d [2] 39 5c [2] 77 50 [2] 7b 5a [2] 6c 51 [2] 77 1f [2] 4a }

  condition:
    any of them
}