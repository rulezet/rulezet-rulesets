rule TTP_XOR_MULT_DOSStub_030f {
  strings:
    $key_030f = { 57 67 [2] 23 7f [2] 64 7d [2] 23 6c [2] 6d 60 [2] 61 6a [2] 76 61 [2] 6d 2f [2] 50 }

  condition:
    any of them
}