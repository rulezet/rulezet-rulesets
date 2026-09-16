rule TTP_XOR_MULT_DOSStub_2b2c {
  strings:
    $key_2b2c = { 7f 44 [2] 0b 5c [2] 4c 5e [2] 0b 4f [2] 45 43 [2] 49 49 [2] 5e 42 [2] 45 0c [2] 78 }

  condition:
    any of them
}