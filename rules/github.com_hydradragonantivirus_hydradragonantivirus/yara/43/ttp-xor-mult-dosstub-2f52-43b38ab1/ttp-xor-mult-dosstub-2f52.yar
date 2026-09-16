rule TTP_XOR_MULT_DOSStub_2f52 {
  strings:
    $key_2f52 = { 7b 3a [2] 0f 22 [2] 48 20 [2] 0f 31 [2] 41 3d [2] 4d 37 [2] 5a 3c [2] 41 72 [2] 7c }

  condition:
    any of them
}