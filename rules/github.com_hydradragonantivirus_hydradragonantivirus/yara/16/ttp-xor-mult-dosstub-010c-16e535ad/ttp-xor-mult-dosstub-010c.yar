rule TTP_XOR_MULT_DOSStub_010c {
  strings:
    $key_010c = { 55 64 [2] 21 7c [2] 66 7e [2] 21 6f [2] 6f 63 [2] 63 69 [2] 74 62 [2] 6f 2c [2] 52 }

  condition:
    any of them
}