rule TTP_XOR_MULT_DOSStub_2714 {
  strings:
    $key_2714 = { 73 7c [2] 07 64 [2] 40 66 [2] 07 77 [2] 49 7b [2] 45 71 [2] 52 7a [2] 49 34 [2] 74 }

  condition:
    any of them
}