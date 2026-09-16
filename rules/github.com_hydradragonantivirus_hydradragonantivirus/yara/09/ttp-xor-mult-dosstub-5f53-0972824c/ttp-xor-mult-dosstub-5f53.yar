rule TTP_XOR_MULT_DOSStub_5f53 {
  strings:
    $key_5f53 = { 0b 3b [2] 7f 23 [2] 38 21 [2] 7f 30 [2] 31 3c [2] 3d 36 [2] 2a 3d [2] 31 73 [2] 0c }

  condition:
    any of them
}