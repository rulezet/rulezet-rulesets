rule TTP_XOR_MULT_DOSStub_f8ef {
  strings:
    $key_f8ef = { ac 87 [2] d8 9f [2] 9f 9d [2] d8 8c [2] 96 80 [2] 9a 8a [2] 8d 81 [2] 96 cf [2] ab }

  condition:
    any of them
}