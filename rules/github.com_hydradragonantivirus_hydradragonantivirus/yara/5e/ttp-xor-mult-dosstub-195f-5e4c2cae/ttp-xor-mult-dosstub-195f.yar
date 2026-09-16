rule TTP_XOR_MULT_DOSStub_195f {
  strings:
    $key_195f = { 4d 37 [2] 39 2f [2] 7e 2d [2] 39 3c [2] 77 30 [2] 7b 3a [2] 6c 31 [2] 77 7f [2] 4a }

  condition:
    any of them
}