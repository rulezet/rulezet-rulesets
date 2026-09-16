rule TTP_XOR_MULT_DOSStub_350c {
  strings:
    $key_350c = { 61 64 [2] 15 7c [2] 52 7e [2] 15 6f [2] 5b 63 [2] 57 69 [2] 40 62 [2] 5b 2c [2] 66 }

  condition:
    any of them
}