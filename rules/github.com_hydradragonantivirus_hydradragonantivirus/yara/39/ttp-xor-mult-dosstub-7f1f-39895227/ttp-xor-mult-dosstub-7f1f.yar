rule TTP_XOR_MULT_DOSStub_7f1f {
  strings:
    $key_7f1f = { 2b 77 [2] 5f 6f [2] 18 6d [2] 5f 7c [2] 11 70 [2] 1d 7a [2] 0a 71 [2] 11 3f [2] 2c }

  condition:
    any of them
}