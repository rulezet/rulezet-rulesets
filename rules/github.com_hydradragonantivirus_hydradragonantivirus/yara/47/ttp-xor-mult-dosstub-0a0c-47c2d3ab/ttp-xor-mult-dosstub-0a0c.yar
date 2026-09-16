rule TTP_XOR_MULT_DOSStub_0a0c {
  strings:
    $key_0a0c = { 5e 64 [2] 2a 7c [2] 6d 7e [2] 2a 6f [2] 64 63 [2] 68 69 [2] 7f 62 [2] 64 2c [2] 59 }

  condition:
    any of them
}