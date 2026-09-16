rule TTP_XOR_MULT_DOSStub_200c {
  strings:
    $key_200c = { 74 64 [2] 00 7c [2] 47 7e [2] 00 6f [2] 4e 63 [2] 42 69 [2] 55 62 [2] 4e 2c [2] 73 }

  condition:
    any of them
}