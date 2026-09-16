rule TTP_XOR_MULT_DOSStub_f830 {
  strings:
    $key_f830 = { ac 58 [2] d8 40 [2] 9f 42 [2] d8 53 [2] 96 5f [2] 9a 55 [2] 8d 5e [2] 96 10 [2] ab }

  condition:
    any of them
}