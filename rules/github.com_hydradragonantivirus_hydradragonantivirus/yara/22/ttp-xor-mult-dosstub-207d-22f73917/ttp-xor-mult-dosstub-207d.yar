rule TTP_XOR_MULT_DOSStub_207d {
  strings:
    $key_207d = { 74 15 [2] 00 0d [2] 47 0f [2] 00 1e [2] 4e 12 [2] 42 18 [2] 55 13 [2] 4e 5d [2] 73 }

  condition:
    any of them
}