rule TTP_XOR_MULT_DOSStub_f852 {
  strings:
    $key_f852 = { ac 3a [2] d8 22 [2] 9f 20 [2] d8 31 [2] 96 3d [2] 9a 37 [2] 8d 3c [2] 96 72 [2] ab }

  condition:
    any of them
}