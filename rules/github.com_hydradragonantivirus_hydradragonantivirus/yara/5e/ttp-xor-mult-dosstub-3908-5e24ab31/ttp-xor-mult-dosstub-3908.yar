rule TTP_XOR_MULT_DOSStub_3908 {
  strings:
    $key_3908 = { 6d 60 [2] 19 78 [2] 5e 7a [2] 19 6b [2] 57 67 [2] 5b 6d [2] 4c 66 [2] 57 28 [2] 6a }

  condition:
    any of them
}