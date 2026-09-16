rule TTP_XOR_MULT_DOSStub_f870 {
  strings:
    $key_f870 = { ac 18 [2] d8 00 [2] 9f 02 [2] d8 13 [2] 96 1f [2] 9a 15 [2] 8d 1e [2] 96 50 [2] ab }

  condition:
    any of them
}