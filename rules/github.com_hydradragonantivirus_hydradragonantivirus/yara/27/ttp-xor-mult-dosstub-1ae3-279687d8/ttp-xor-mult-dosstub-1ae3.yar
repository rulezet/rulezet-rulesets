rule TTP_XOR_MULT_DOSStub_1ae3 {
  strings:
    $key_1ae3 = { 4e 8b [2] 3a 93 [2] 7d 91 [2] 3a 80 [2] 74 8c [2] 78 86 [2] 6f 8d [2] 74 c3 [2] 49 }

  condition:
    any of them
}