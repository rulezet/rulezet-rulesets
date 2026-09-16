rule TTP_XOR_MULT_DOSStub_1833 {
  strings:
    $key_1833 = { 4c 5b [2] 38 43 [2] 7f 41 [2] 38 50 [2] 76 5c [2] 7a 56 [2] 6d 5d [2] 76 13 [2] 4b }

  condition:
    any of them
}