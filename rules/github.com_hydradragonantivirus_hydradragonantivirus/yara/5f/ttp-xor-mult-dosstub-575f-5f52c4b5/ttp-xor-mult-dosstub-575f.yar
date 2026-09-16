rule TTP_XOR_MULT_DOSStub_575f {
  strings:
    $key_575f = { 03 37 [2] 77 2f [2] 30 2d [2] 77 3c [2] 39 30 [2] 35 3a [2] 22 31 [2] 39 7f [2] 04 }

  condition:
    any of them
}