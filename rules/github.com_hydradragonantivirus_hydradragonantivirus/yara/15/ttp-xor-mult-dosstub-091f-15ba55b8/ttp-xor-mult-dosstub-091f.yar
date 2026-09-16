rule TTP_XOR_MULT_DOSStub_091f {
  strings:
    $key_091f = { 5d 77 [2] 29 6f [2] 6e 6d [2] 29 7c [2] 67 70 [2] 6b 7a [2] 7c 71 [2] 67 3f [2] 5a }

  condition:
    any of them
}