rule TTP_XOR_MULT_DOSStub_f80c {
  strings:
    $key_f80c = { ac 64 [2] d8 7c [2] 9f 7e [2] d8 6f [2] 96 63 [2] 9a 69 [2] 8d 62 [2] 96 2c [2] ab }

  condition:
    any of them
}