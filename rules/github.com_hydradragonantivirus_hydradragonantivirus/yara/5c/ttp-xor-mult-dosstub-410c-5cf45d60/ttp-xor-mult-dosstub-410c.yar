rule TTP_XOR_MULT_DOSStub_410c {
  strings:
    $key_410c = { 15 64 [2] 61 7c [2] 26 7e [2] 61 6f [2] 2f 63 [2] 23 69 [2] 34 62 [2] 2f 2c [2] 12 }

  condition:
    any of them
}