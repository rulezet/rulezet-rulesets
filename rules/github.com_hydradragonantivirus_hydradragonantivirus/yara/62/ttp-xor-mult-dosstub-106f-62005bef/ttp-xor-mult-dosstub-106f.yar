rule TTP_XOR_MULT_DOSStub_106f {
  strings:
    $key_106f = { 44 07 [2] 30 1f [2] 77 1d [2] 30 0c [2] 7e 00 [2] 72 0a [2] 65 01 [2] 7e 4f [2] 43 }

  condition:
    any of them
}