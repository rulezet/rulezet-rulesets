rule TTP_XOR_MULT_DOSStub_0824 {
  strings:
    $key_0824 = { 5c 4c [2] 28 54 [2] 6f 56 [2] 28 47 [2] 66 4b [2] 6a 41 [2] 7d 4a [2] 66 04 [2] 5b }

  condition:
    any of them
}