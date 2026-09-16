rule TTP_XOR_MULT_DOSStub_247f {
  strings:
    $key_247f = { 70 17 [2] 04 0f [2] 43 0d [2] 04 1c [2] 4a 10 [2] 46 1a [2] 51 11 [2] 4a 5f [2] 77 }

  condition:
    any of them
}