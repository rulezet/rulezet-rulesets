rule TTP_XOR_MULT_DOSStub_577f {
  strings:
    $key_577f = { 03 17 [2] 77 0f [2] 30 0d [2] 77 1c [2] 39 10 [2] 35 1a [2] 22 11 [2] 39 5f [2] 04 }

  condition:
    any of them
}