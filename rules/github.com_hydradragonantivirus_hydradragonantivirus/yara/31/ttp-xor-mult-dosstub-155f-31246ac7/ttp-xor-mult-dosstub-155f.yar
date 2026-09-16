rule TTP_XOR_MULT_DOSStub_155f {
  strings:
    $key_155f = { 41 37 [2] 35 2f [2] 72 2d [2] 35 3c [2] 7b 30 [2] 77 3a [2] 60 31 [2] 7b 7f [2] 46 }

  condition:
    any of them
}