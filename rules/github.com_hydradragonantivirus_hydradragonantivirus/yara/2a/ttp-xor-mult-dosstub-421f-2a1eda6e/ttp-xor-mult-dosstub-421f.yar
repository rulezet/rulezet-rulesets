rule TTP_XOR_MULT_DOSStub_421f {
  strings:
    $key_421f = { 16 77 [2] 62 6f [2] 25 6d [2] 62 7c [2] 2c 70 [2] 20 7a [2] 37 71 [2] 2c 3f [2] 11 }

  condition:
    any of them
}