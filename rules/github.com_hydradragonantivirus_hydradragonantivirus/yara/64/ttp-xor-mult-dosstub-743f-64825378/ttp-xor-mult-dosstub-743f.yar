rule TTP_XOR_MULT_DOSStub_743f {
  strings:
    $key_743f = { 20 57 [2] 54 4f [2] 13 4d [2] 54 5c [2] 1a 50 [2] 16 5a [2] 01 51 [2] 1a 1f [2] 27 }

  condition:
    any of them
}