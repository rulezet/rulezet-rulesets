rule TTP_XOR_MULT_DOSStub_4f22 {
  strings:
    $key_4f22 = { 1b 4a [2] 6f 52 [2] 28 50 [2] 6f 41 [2] 21 4d [2] 2d 47 [2] 3a 4c [2] 21 02 [2] 1c }

  condition:
    any of them
}