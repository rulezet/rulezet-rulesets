rule TTP_XOR_MULT_DOSStub_f853 {
  strings:
    $key_f853 = { ac 3b [2] d8 23 [2] 9f 21 [2] d8 30 [2] 96 3c [2] 9a 36 [2] 8d 3d [2] 96 73 [2] ab }

  condition:
    any of them
}