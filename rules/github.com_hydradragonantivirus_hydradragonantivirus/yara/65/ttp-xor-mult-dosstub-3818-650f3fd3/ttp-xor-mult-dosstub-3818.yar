rule TTP_XOR_MULT_DOSStub_3818 {
  strings:
    $key_3818 = { 6c 70 [2] 18 68 [2] 5f 6a [2] 18 7b [2] 56 77 [2] 5a 7d [2] 4d 76 [2] 56 38 [2] 6b }

  condition:
    any of them
}