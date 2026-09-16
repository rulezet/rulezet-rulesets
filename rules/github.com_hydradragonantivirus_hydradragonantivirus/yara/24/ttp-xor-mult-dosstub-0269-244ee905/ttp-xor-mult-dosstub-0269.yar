rule TTP_XOR_MULT_DOSStub_0269 {
  strings:
    $key_0269 = { 56 01 [2] 22 19 [2] 65 1b [2] 22 0a [2] 6c 06 [2] 60 0c [2] 77 07 [2] 6c 49 [2] 51 }

  condition:
    any of them
}