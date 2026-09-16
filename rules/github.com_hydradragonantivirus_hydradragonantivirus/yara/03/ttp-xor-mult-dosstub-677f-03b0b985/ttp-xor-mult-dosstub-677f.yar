rule TTP_XOR_MULT_DOSStub_677f {
  strings:
    $key_677f = { 33 17 [2] 47 0f [2] 00 0d [2] 47 1c [2] 09 10 [2] 05 1a [2] 12 11 [2] 09 5f [2] 34 }

  condition:
    any of them
}