rule TTP_XOR_MULT_DOSStub_3925 {
  strings:
    $key_3925 = { 6d 4d [2] 19 55 [2] 5e 57 [2] 19 46 [2] 57 4a [2] 5b 40 [2] 4c 4b [2] 57 05 [2] 6a }

  condition:
    any of them
}