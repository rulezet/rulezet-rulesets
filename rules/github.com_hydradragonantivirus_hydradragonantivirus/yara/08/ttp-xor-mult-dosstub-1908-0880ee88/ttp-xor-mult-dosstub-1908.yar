rule TTP_XOR_MULT_DOSStub_1908 {
  strings:
    $key_1908 = { 4d 60 [2] 39 78 [2] 7e 7a [2] 39 6b [2] 77 67 [2] 7b 6d [2] 6c 66 [2] 77 28 [2] 4a }

  condition:
    any of them
}