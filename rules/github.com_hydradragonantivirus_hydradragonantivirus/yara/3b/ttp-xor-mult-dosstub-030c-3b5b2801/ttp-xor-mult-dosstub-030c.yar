rule TTP_XOR_MULT_DOSStub_030c {
  strings:
    $key_030c = { 57 64 [2] 23 7c [2] 64 7e [2] 23 6f [2] 6d 63 [2] 61 69 [2] 76 62 [2] 6d 2c [2] 50 }

  condition:
    any of them
}