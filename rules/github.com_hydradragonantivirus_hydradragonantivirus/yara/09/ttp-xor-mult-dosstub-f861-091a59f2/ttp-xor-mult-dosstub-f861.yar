rule TTP_XOR_MULT_DOSStub_f861 {
  strings:
    $key_f861 = { ac 09 [2] d8 11 [2] 9f 13 [2] d8 02 [2] 96 0e [2] 9a 04 [2] 8d 0f [2] 96 41 [2] ab }

  condition:
    any of them
}