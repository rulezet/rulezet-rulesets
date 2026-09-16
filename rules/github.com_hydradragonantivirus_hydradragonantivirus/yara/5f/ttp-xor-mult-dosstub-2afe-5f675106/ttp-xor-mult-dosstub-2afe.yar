rule TTP_XOR_MULT_DOSStub_2afe {
  strings:
    $key_2afe = { 7e 96 [2] 0a 8e [2] 4d 8c [2] 0a 9d [2] 44 91 [2] 48 9b [2] 5f 90 [2] 44 de [2] 79 }

  condition:
    any of them
}