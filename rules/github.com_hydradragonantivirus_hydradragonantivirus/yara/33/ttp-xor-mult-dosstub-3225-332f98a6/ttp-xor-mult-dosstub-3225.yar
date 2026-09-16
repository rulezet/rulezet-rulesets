rule TTP_XOR_MULT_DOSStub_3225 {
  strings:
    $key_3225 = { 66 4d [2] 12 55 [2] 55 57 [2] 12 46 [2] 5c 4a [2] 50 40 [2] 47 4b [2] 5c 05 [2] 61 }

  condition:
    any of them
}