rule TTP_XOR_MULT_DOSStub_2704 {
  strings:
    $key_2704 = { 73 6c [2] 07 74 [2] 40 76 [2] 07 67 [2] 49 6b [2] 45 61 [2] 52 6a [2] 49 24 [2] 74 }

  condition:
    any of them
}