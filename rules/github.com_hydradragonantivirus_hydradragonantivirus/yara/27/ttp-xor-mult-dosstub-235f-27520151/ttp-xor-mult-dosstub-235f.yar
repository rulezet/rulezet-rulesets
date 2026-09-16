rule TTP_XOR_MULT_DOSStub_235f {
  strings:
    $key_235f = { 77 37 [2] 03 2f [2] 44 2d [2] 03 3c [2] 4d 30 [2] 41 3a [2] 56 31 [2] 4d 7f [2] 70 }

  condition:
    any of them
}