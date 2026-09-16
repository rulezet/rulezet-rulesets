rule TTP_XOR_MULT_DOSStub_f83d {
  strings:
    $key_f83d = { ac 55 [2] d8 4d [2] 9f 4f [2] d8 5e [2] 96 52 [2] 9a 58 [2] 8d 53 [2] 96 1d [2] ab }

  condition:
    any of them
}