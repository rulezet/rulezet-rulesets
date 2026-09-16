rule TTP_XOR_MULT_DOSStub_f8e0 {
  strings:
    $key_f8e0 = { ac 88 [2] d8 90 [2] 9f 92 [2] d8 83 [2] 96 8f [2] 9a 85 [2] 8d 8e [2] 96 c0 [2] ab }

  condition:
    any of them
}