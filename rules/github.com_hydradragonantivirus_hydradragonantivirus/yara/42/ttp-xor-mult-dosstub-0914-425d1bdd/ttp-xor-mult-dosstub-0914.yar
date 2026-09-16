rule TTP_XOR_MULT_DOSStub_0914 {
  strings:
    $key_0914 = { 5d 7c [2] 29 64 [2] 6e 66 [2] 29 77 [2] 67 7b [2] 6b 71 [2] 7c 7a [2] 67 34 [2] 5a }

  condition:
    any of them
}