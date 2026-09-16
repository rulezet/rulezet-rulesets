rule TTP_XOR_MULT_DOSStub_f8f1 {
  strings:
    $key_f8f1 = { ac 99 [2] d8 81 [2] 9f 83 [2] d8 92 [2] 96 9e [2] 9a 94 [2] 8d 9f [2] 96 d1 [2] ab }

  condition:
    any of them
}