rule TTP_XOR_MULT_DOSStub_4b4c {
  strings:
    $key_4b4c = { 1f 24 [2] 6b 3c [2] 2c 3e [2] 6b 2f [2] 25 23 [2] 29 29 [2] 3e 22 [2] 25 6c [2] 18 }

  condition:
    any of them
}