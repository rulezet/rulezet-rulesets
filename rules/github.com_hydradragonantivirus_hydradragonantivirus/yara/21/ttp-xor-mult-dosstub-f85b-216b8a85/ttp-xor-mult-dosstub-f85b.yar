rule TTP_XOR_MULT_DOSStub_f85b {
  strings:
    $key_f85b = { ac 33 [2] d8 2b [2] 9f 29 [2] d8 38 [2] 96 34 [2] 9a 3e [2] 8d 35 [2] 96 7b [2] ab }

  condition:
    any of them
}