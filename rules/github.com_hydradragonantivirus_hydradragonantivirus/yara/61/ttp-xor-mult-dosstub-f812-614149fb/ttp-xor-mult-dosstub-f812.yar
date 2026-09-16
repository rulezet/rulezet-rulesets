rule TTP_XOR_MULT_DOSStub_f812 {
  strings:
    $key_f812 = { ac 7a [2] d8 62 [2] 9f 60 [2] d8 71 [2] 96 7d [2] 9a 77 [2] 8d 7c [2] 96 32 [2] ab }

  condition:
    any of them
}