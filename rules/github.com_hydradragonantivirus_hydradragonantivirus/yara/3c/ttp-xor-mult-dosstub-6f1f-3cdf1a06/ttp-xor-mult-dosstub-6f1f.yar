rule TTP_XOR_MULT_DOSStub_6f1f {
  strings:
    $key_6f1f = { 3b 77 [2] 4f 6f [2] 08 6d [2] 4f 7c [2] 01 70 [2] 0d 7a [2] 1a 71 [2] 01 3f [2] 3c }

  condition:
    any of them
}