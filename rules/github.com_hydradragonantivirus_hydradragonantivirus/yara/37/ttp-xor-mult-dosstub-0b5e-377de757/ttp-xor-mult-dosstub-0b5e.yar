rule TTP_XOR_MULT_DOSStub_0b5e {
  strings:
    $key_0b5e = { 5f 36 [2] 2b 2e [2] 6c 2c [2] 2b 3d [2] 65 31 [2] 69 3b [2] 7e 30 [2] 65 7e [2] 58 }

  condition:
    any of them
}