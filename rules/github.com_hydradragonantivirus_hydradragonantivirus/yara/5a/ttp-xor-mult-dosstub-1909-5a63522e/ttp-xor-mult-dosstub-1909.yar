rule TTP_XOR_MULT_DOSStub_1909 {
  strings:
    $key_1909 = { 4d 61 [2] 39 79 [2] 7e 7b [2] 39 6a [2] 77 66 [2] 7b 6c [2] 6c 67 [2] 77 29 [2] 4a }

  condition:
    any of them
}