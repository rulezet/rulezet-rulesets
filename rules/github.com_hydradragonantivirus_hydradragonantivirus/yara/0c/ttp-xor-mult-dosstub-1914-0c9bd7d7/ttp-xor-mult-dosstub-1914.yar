rule TTP_XOR_MULT_DOSStub_1914 {
  strings:
    $key_1914 = { 4d 7c [2] 39 64 [2] 7e 66 [2] 39 77 [2] 77 7b [2] 7b 71 [2] 6c 7a [2] 77 34 [2] 4a }

  condition:
    any of them
}