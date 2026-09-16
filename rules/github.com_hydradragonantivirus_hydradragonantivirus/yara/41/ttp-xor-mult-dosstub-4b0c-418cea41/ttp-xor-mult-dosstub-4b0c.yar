rule TTP_XOR_MULT_DOSStub_4b0c {
  strings:
    $key_4b0c = { 1f 64 [2] 6b 7c [2] 2c 7e [2] 6b 6f [2] 25 63 [2] 29 69 [2] 3e 62 [2] 25 2c [2] 18 }

  condition:
    any of them
}