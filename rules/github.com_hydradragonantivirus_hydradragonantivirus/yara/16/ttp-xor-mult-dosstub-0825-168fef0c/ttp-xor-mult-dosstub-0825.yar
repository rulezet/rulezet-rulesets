rule TTP_XOR_MULT_DOSStub_0825 {
  strings:
    $key_0825 = { 5c 4d [2] 28 55 [2] 6f 57 [2] 28 46 [2] 66 4a [2] 6a 40 [2] 7d 4b [2] 66 05 [2] 5b }

  condition:
    any of them
}