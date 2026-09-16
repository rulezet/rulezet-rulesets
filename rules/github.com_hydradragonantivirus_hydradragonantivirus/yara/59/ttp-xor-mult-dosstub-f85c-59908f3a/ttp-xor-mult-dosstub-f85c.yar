rule TTP_XOR_MULT_DOSStub_f85c {
  strings:
    $key_f85c = { ac 34 [2] d8 2c [2] 9f 2e [2] d8 3f [2] 96 33 [2] 9a 39 [2] 8d 32 [2] 96 7c [2] ab }

  condition:
    any of them
}