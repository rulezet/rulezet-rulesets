rule TTP_XOR_MULT_DOSStub_217f {
  strings:
    $key_217f = { 75 17 [2] 01 0f [2] 46 0d [2] 01 1c [2] 4f 10 [2] 43 1a [2] 54 11 [2] 4f 5f [2] 72 }

  condition:
    any of them
}