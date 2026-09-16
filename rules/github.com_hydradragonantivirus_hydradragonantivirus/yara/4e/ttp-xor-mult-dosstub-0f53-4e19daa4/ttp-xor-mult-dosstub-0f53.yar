rule TTP_XOR_MULT_DOSStub_0f53 {
  strings:
    $key_0f53 = { 5b 3b [2] 2f 23 [2] 68 21 [2] 2f 30 [2] 61 3c [2] 6d 36 [2] 7a 3d [2] 61 73 [2] 5c }

  condition:
    any of them
}