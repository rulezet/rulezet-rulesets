rule TTP_XOR_MULT_DOSStub_6cf2 {
  strings:
    $key_6cf2 = { 38 9a [2] 4c 82 [2] 0b 80 [2] 4c 91 [2] 02 9d [2] 0e 97 [2] 19 9c [2] 02 d2 [2] 3f }

  condition:
    any of them
}