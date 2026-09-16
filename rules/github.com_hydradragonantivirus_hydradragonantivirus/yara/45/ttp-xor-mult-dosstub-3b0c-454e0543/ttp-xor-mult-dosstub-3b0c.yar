rule TTP_XOR_MULT_DOSStub_3b0c {
  strings:
    $key_3b0c = { 6f 64 [2] 1b 7c [2] 5c 7e [2] 1b 6f [2] 55 63 [2] 59 69 [2] 4e 62 [2] 55 2c [2] 68 }

  condition:
    any of them
}