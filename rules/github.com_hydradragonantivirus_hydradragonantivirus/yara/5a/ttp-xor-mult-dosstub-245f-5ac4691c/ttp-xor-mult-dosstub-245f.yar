rule TTP_XOR_MULT_DOSStub_245f {
  strings:
    $key_245f = { 70 37 [2] 04 2f [2] 43 2d [2] 04 3c [2] 4a 30 [2] 46 3a [2] 51 31 [2] 4a 7f [2] 77 }

  condition:
    any of them
}