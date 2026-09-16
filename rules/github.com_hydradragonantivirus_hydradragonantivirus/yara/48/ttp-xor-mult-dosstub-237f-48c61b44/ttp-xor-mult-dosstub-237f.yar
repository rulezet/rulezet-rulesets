rule TTP_XOR_MULT_DOSStub_237f {
  strings:
    $key_237f = { 77 17 [2] 03 0f [2] 44 0d [2] 03 1c [2] 4d 10 [2] 41 1a [2] 56 11 [2] 4d 5f [2] 70 }

  condition:
    any of them
}