rule TTP_XOR_MULT_DOSStub_f81f {
  strings:
    $key_f81f = { ac 77 [2] d8 6f [2] 9f 6d [2] d8 7c [2] 96 70 [2] 9a 7a [2] 8d 71 [2] 96 3f [2] ab }

  condition:
    any of them
}