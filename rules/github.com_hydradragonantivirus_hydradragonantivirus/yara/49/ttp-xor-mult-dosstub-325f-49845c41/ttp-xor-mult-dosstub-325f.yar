rule TTP_XOR_MULT_DOSStub_325f {
  strings:
    $key_325f = { 66 37 [2] 12 2f [2] 55 2d [2] 12 3c [2] 5c 30 [2] 50 3a [2] 47 31 [2] 5c 7f [2] 61 }

  condition:
    any of them
}