rule TTP_XOR_MULT_DOSStub_600c {
  strings:
    $key_600c = { 34 64 [2] 40 7c [2] 07 7e [2] 40 6f [2] 0e 63 [2] 02 69 [2] 15 62 [2] 0e 2c [2] 33 }

  condition:
    any of them
}