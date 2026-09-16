rule TTP_XOR_MULT_DOSStub_2a0c {
  strings:
    $key_2a0c = { 7e 64 [2] 0a 7c [2] 4d 7e [2] 0a 6f [2] 44 63 [2] 48 69 [2] 5f 62 [2] 44 2c [2] 79 }

  condition:
    any of them
}