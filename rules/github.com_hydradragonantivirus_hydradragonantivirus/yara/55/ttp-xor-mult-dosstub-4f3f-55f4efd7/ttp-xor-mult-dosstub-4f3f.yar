rule TTP_XOR_MULT_DOSStub_4f3f {
  strings:
    $key_4f3f = { 1b 57 [2] 6f 4f [2] 28 4d [2] 6f 5c [2] 21 50 [2] 2d 5a [2] 3a 51 [2] 21 1f [2] 1c }

  condition:
    any of them
}