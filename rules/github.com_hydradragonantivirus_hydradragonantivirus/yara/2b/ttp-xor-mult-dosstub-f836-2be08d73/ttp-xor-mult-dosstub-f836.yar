rule TTP_XOR_MULT_DOSStub_f836 {
  strings:
    $key_f836 = { ac 5e [2] d8 46 [2] 9f 44 [2] d8 55 [2] 96 59 [2] 9a 53 [2] 8d 58 [2] 96 16 [2] ab }

  condition:
    any of them
}