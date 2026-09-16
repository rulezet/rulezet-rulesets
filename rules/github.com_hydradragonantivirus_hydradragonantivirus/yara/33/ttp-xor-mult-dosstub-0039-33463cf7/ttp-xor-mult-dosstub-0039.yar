rule TTP_XOR_MULT_DOSStub_0039 {
  strings:
    $key_0039 = { 54 51 [2] 20 49 [2] 67 4b [2] 20 5a [2] 6e 56 [2] 62 5c [2] 75 57 [2] 6e 19 [2] 53 }

  condition:
    any of them
}