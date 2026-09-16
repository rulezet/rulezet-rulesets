rule TTP_XOR_MULT_DOSStub_3b2c {
  strings:
    $key_3b2c = { 6f 44 [2] 1b 5c [2] 5c 5e [2] 1b 4f [2] 55 43 [2] 59 49 [2] 4e 42 [2] 55 0c [2] 68 }

  condition:
    any of them
}