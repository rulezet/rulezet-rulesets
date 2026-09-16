rule TTP_XOR_MULT_DOSStub_351f {
  strings:
    $key_351f = { 61 77 [2] 15 6f [2] 52 6d [2] 15 7c [2] 5b 70 [2] 57 7a [2] 40 71 [2] 5b 3f [2] 66 }

  condition:
    any of them
}