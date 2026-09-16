rule TTP_XOR_MULT_DOSStub_246f {
  strings:
    $key_246f = { 70 07 [2] 04 1f [2] 43 1d [2] 04 0c [2] 4a 00 [2] 46 0a [2] 51 01 [2] 4a 4f [2] 77 }

  condition:
    any of them
}