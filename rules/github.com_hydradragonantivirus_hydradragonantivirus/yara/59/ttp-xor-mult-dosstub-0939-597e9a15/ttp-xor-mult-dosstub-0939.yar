rule TTP_XOR_MULT_DOSStub_0939 {
  strings:
    $key_0939 = { 5d 51 [2] 29 49 [2] 6e 4b [2] 29 5a [2] 67 56 [2] 6b 5c [2] 7c 57 [2] 67 19 [2] 5a }

  condition:
    any of them
}