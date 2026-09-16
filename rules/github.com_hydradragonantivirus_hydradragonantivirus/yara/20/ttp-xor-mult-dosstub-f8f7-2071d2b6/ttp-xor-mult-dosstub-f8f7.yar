rule TTP_XOR_MULT_DOSStub_f8f7 {
  strings:
    $key_f8f7 = { ac 9f [2] d8 87 [2] 9f 85 [2] d8 94 [2] 96 98 [2] 9a 92 [2] 8d 99 [2] 96 d7 [2] ab }

  condition:
    any of them
}