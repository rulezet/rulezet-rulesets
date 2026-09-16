rule TTP_XOR_MULT_DOSStub_f82c {
  strings:
    $key_f82c = { ac 44 [2] d8 5c [2] 9f 5e [2] d8 4f [2] 96 43 [2] 9a 49 [2] 8d 42 [2] 96 0c [2] ab }

  condition:
    any of them
}