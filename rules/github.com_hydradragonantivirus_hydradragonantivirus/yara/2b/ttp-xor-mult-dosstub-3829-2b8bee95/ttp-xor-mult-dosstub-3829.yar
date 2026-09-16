rule TTP_XOR_MULT_DOSStub_3829 {
  strings:
    $key_3829 = { 6c 41 [2] 18 59 [2] 5f 5b [2] 18 4a [2] 56 46 [2] 5a 4c [2] 4d 47 [2] 56 09 [2] 6b }

  condition:
    any of them
}