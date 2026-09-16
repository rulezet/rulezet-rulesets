rule TTP_XOR_MULT_DOSStub_031f {
  strings:
    $key_031f = { 57 77 [2] 23 6f [2] 64 6d [2] 23 7c [2] 6d 70 [2] 61 7a [2] 76 71 [2] 6d 3f [2] 50 }

  condition:
    any of them
}