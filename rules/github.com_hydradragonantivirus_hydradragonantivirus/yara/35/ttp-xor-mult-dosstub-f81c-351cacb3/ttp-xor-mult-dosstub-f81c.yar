rule TTP_XOR_MULT_DOSStub_f81c {
  strings:
    $key_f81c = { ac 74 [2] d8 6c [2] 9f 6e [2] d8 7f [2] 96 73 [2] 9a 79 [2] 8d 72 [2] 96 3c [2] ab }

  condition:
    any of them
}