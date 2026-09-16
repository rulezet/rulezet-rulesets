rule TTP_XOR_MULT_DOSStub_2832 {
  strings:
    $key_2832 = { 7c 5a [2] 08 42 [2] 4f 40 [2] 08 51 [2] 46 5d [2] 4a 57 [2] 5d 5c [2] 46 12 [2] 7b }

  condition:
    any of them
}