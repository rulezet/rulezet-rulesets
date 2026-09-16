rule TTP_XOR_MULT_DOSStub_0952 {
  strings:
    $key_0952 = { 5d 3a [2] 29 22 [2] 6e 20 [2] 29 31 [2] 67 3d [2] 6b 37 [2] 7c 3c [2] 67 72 [2] 5a }

  condition:
    any of them
}