rule TTP_XOR_MULT_DOSStub_5f22 {
  strings:
    $key_5f22 = { 0b 4a [2] 7f 52 [2] 38 50 [2] 7f 41 [2] 31 4d [2] 3d 47 [2] 2a 4c [2] 31 02 [2] 0c }

  condition:
    any of them
}