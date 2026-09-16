rule TTP_XOR_MULT_DOSStub_f8fe {
  strings:
    $key_f8fe = { ac 96 [2] d8 8e [2] 9f 8c [2] d8 9d [2] 96 91 [2] 9a 9b [2] 8d 90 [2] 96 de [2] ab }

  condition:
    any of them
}