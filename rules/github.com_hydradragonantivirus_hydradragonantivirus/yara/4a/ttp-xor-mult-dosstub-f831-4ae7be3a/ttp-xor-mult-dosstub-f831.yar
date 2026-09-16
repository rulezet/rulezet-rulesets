rule TTP_XOR_MULT_DOSStub_f831 {
  strings:
    $key_f831 = { ac 59 [2] d8 41 [2] 9f 43 [2] d8 52 [2] 96 5e [2] 9a 54 [2] 8d 5f [2] 96 11 [2] ab }

  condition:
    any of them
}