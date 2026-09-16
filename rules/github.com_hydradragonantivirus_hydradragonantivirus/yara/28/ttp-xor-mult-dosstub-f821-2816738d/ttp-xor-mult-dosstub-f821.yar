rule TTP_XOR_MULT_DOSStub_f821 {
  strings:
    $key_f821 = { ac 49 [2] d8 51 [2] 9f 53 [2] d8 42 [2] 96 4e [2] 9a 44 [2] 8d 4f [2] 96 01 [2] ab }

  condition:
    any of them
}