rule TTP_XOR_MULT_DOSStub_0839 {
  strings:
    $key_0839 = { 5c 51 [2] 28 49 [2] 6f 4b [2] 28 5a [2] 66 56 [2] 6a 5c [2] 7d 57 [2] 66 19 [2] 5b }

  condition:
    any of them
}