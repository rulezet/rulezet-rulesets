rule TTP_XOR_MULT_DOSStub_f810 {
  strings:
    $key_f810 = { ac 78 [2] d8 60 [2] 9f 62 [2] d8 73 [2] 96 7f [2] 9a 75 [2] 8d 7e [2] 96 30 [2] ab }

  condition:
    any of them
}