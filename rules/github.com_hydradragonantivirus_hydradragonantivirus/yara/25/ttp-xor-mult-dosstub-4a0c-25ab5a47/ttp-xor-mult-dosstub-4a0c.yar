rule TTP_XOR_MULT_DOSStub_4a0c {
  strings:
    $key_4a0c = { 1e 64 [2] 6a 7c [2] 2d 7e [2] 6a 6f [2] 24 63 [2] 28 69 [2] 3f 62 [2] 24 2c [2] 19 }

  condition:
    any of them
}