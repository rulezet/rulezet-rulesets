rule TTP_XOR_MULT_DOSStub_0209 {
  strings:
    $key_0209 = { 56 61 [2] 22 79 [2] 65 7b [2] 22 6a [2] 6c 66 [2] 60 6c [2] 77 67 [2] 6c 29 [2] 51 }

  condition:
    any of them
}