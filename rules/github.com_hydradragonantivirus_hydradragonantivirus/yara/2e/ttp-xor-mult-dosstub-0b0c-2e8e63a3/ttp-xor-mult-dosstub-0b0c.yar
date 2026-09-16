rule TTP_XOR_MULT_DOSStub_0b0c {
  strings:
    $key_0b0c = { 5f 64 [2] 2b 7c [2] 6c 7e [2] 2b 6f [2] 65 63 [2] 69 69 [2] 7e 62 [2] 65 2c [2] 58 }

  condition:
    any of them
}