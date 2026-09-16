rule TTP_XOR_MULT_DOSStub_3824 {
  strings:
    $key_3824 = { 6c 4c [2] 18 54 [2] 5f 56 [2] 18 47 [2] 56 4b [2] 5a 41 [2] 4d 4a [2] 56 04 [2] 6b }

  condition:
    any of them
}