rule TTP_XOR_MULT_DOSStub_2ae3 {
  strings:
    $key_2ae3 = { 7e 8b [2] 0a 93 [2] 4d 91 [2] 0a 80 [2] 44 8c [2] 48 86 [2] 5f 8d [2] 44 c3 [2] 79 }

  condition:
    any of them
}