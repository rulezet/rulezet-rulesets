rule TTP_XOR_MULT_DOSStub_5ff2 {
  strings:
    $key_5ff2 = { 0b 9a [2] 7f 82 [2] 38 80 [2] 7f 91 [2] 31 9d [2] 3d 97 [2] 2a 9c [2] 31 d2 [2] 0c }

  condition:
    any of them
}