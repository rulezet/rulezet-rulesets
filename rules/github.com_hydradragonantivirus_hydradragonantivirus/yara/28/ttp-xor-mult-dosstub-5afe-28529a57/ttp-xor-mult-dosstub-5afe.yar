rule TTP_XOR_MULT_DOSStub_5afe {
  strings:
    $key_5afe = { 0e 96 [2] 7a 8e [2] 3d 8c [2] 7a 9d [2] 34 91 [2] 38 9b [2] 2f 90 [2] 34 de [2] 09 }

  condition:
    any of them
}