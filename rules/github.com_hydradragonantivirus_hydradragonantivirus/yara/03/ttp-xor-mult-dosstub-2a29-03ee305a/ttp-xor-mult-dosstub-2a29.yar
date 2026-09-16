rule TTP_XOR_MULT_DOSStub_2a29 {
  strings:
    $key_2a29 = { 7e 41 [2] 0a 59 [2] 4d 5b [2] 0a 4a [2] 44 46 [2] 48 4c [2] 5f 47 [2] 44 09 [2] 79 }

  condition:
    any of them
}