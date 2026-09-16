rule TTP_XOR_MULT_DOSStub_3828 {
  strings:
    $key_3828 = { 6c 40 [2] 18 58 [2] 5f 5a [2] 18 4b [2] 56 47 [2] 5a 4d [2] 4d 46 [2] 56 08 [2] 6b }

  condition:
    any of them
}