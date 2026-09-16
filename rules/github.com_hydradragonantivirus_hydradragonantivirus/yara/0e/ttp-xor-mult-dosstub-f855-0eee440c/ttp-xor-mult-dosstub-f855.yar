rule TTP_XOR_MULT_DOSStub_f855 {
  strings:
    $key_f855 = { ac 3d [2] d8 25 [2] 9f 27 [2] d8 36 [2] 96 3a [2] 9a 30 [2] 8d 3b [2] 96 75 [2] ab }

  condition:
    any of them
}