rule TTP_XOR_MULT_DOSStub_440c {
  strings:
    $key_440c = { 10 64 [2] 64 7c [2] 23 7e [2] 64 6f [2] 2a 63 [2] 26 69 [2] 31 62 [2] 2a 2c [2] 17 }

  condition:
    any of them
}