rule TTP_XOR_MULT_DOSStub_6632 {
  strings:
    $key_6632 = { 32 5a [2] 46 42 [2] 01 40 [2] 46 51 [2] 08 5d [2] 04 57 [2] 13 5c [2] 08 12 [2] 35 }

  condition:
    any of them
}