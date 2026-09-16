rule TTP_XOR_MULT_DOSStub_6d2c {
  strings:
    $key_6d2c = { 39 44 [2] 4d 5c [2] 0a 5e [2] 4d 4f [2] 03 43 [2] 0f 49 [2] 18 42 [2] 03 0c [2] 3e }

  condition:
    any of them
}