rule TTP_XOR_MULT_DOSStub_3962 {
  strings:
    $key_3962 = { 6d 0a [2] 19 12 [2] 5e 10 [2] 19 01 [2] 57 0d [2] 5b 07 [2] 4c 0c [2] 57 42 [2] 6a }

  condition:
    any of them
}