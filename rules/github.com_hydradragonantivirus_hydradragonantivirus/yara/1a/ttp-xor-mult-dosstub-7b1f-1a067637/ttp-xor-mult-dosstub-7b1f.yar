rule TTP_XOR_MULT_DOSStub_7b1f {
  strings:
    $key_7b1f = { 2f 77 [2] 5b 6f [2] 1c 6d [2] 5b 7c [2] 15 70 [2] 19 7a [2] 0e 71 [2] 15 3f [2] 28 }

  condition:
    any of them
}