rule TTP_XOR_MULT_DOSStub_1902 {
  strings:
    $key_1902 = { 4d 6a [2] 39 72 [2] 7e 70 [2] 39 61 [2] 77 6d [2] 7b 67 [2] 6c 6c [2] 77 22 [2] 4a }

  condition:
    any of them
}