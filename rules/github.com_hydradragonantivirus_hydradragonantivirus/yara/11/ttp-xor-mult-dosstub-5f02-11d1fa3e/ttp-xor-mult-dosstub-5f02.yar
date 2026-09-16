rule TTP_XOR_MULT_DOSStub_5f02 {
  strings:
    $key_5f02 = { 0b 6a [2] 7f 72 [2] 38 70 [2] 7f 61 [2] 31 6d [2] 3d 67 [2] 2a 6c [2] 31 22 [2] 0c }

  condition:
    any of them
}