rule TTP_XOR_MULT_DOSStub_4afe {
  strings:
    $key_4afe = { 1e 96 [2] 6a 8e [2] 2d 8c [2] 6a 9d [2] 24 91 [2] 28 9b [2] 3f 90 [2] 24 de [2] 19 }

  condition:
    any of them
}