rule TTP_XOR_MULT_DOSStub_f84f {
  strings:
    $key_f84f = { ac 27 [2] d8 3f [2] 9f 3d [2] d8 2c [2] 96 20 [2] 9a 2a [2] 8d 21 [2] 96 6f [2] ab }

  condition:
    any of them
}