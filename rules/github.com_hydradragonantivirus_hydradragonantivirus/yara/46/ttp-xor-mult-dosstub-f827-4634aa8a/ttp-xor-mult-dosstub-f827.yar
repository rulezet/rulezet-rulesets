rule TTP_XOR_MULT_DOSStub_f827 {
  strings:
    $key_f827 = { ac 4f [2] d8 57 [2] 9f 55 [2] d8 44 [2] 96 48 [2] 9a 42 [2] 8d 49 [2] 96 07 [2] ab }

  condition:
    any of them
}