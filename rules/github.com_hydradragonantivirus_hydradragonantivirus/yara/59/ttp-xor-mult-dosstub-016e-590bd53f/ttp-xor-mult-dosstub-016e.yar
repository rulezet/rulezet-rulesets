rule TTP_XOR_MULT_DOSStub_016e {
  strings:
    $key_016e = { 55 06 [2] 21 1e [2] 66 1c [2] 21 0d [2] 6f 01 [2] 63 0b [2] 74 00 [2] 6f 4e [2] 52 }

  condition:
    any of them
}