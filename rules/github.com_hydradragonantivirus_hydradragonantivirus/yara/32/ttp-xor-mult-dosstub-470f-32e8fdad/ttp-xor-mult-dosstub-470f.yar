rule TTP_XOR_MULT_DOSStub_470f {
  strings:
    $key_470f = { 13 67 [2] 67 7f [2] 20 7d [2] 67 6c [2] 29 60 [2] 25 6a [2] 32 61 [2] 29 2f [2] 14 }

  condition:
    any of them
}