rule TTP_XOR_MULT_DOSStub_567f {
  strings:
    $key_567f = { 02 17 [2] 76 0f [2] 31 0d [2] 76 1c [2] 38 10 [2] 34 1a [2] 23 11 [2] 38 5f [2] 05 }

  condition:
    any of them
}