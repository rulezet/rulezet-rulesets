rule TTP_XOR_MULT_DOSStub_5262 {
  strings:
    $key_5262 = { 06 0a [2] 72 12 [2] 35 10 [2] 72 01 [2] 3c 0d [2] 30 07 [2] 27 0c [2] 3c 42 [2] 01 }

  condition:
    any of them
}