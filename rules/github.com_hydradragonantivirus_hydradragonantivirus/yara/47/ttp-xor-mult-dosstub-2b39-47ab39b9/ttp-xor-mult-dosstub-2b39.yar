rule TTP_XOR_MULT_DOSStub_2b39 {
  strings:
    $key_2b39 = { 7f 51 [2] 0b 49 [2] 4c 4b [2] 0b 5a [2] 45 56 [2] 49 5c [2] 5e 57 [2] 45 19 [2] 78 }

  condition:
    any of them
}