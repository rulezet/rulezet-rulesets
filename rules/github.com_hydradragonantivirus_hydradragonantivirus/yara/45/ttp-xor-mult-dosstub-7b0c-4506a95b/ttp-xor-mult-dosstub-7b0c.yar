rule TTP_XOR_MULT_DOSStub_7b0c {
  strings:
    $key_7b0c = { 2f 64 [2] 5b 7c [2] 1c 7e [2] 5b 6f [2] 15 63 [2] 19 69 [2] 0e 62 [2] 15 2c [2] 28 }

  condition:
    any of them
}