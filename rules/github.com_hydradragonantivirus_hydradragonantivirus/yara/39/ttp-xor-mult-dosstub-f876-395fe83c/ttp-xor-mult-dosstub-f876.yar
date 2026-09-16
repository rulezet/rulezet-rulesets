rule TTP_XOR_MULT_DOSStub_f876 {
  strings:
    $key_f876 = { ac 1e [2] d8 06 [2] 9f 04 [2] d8 15 [2] 96 19 [2] 9a 13 [2] 8d 18 [2] 96 56 [2] ab }

  condition:
    any of them
}