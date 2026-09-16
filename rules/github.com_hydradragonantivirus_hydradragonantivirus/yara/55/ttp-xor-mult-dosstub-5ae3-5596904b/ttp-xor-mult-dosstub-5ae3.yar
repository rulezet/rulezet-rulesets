rule TTP_XOR_MULT_DOSStub_5ae3 {
  strings:
    $key_5ae3 = { 0e 8b [2] 7a 93 [2] 3d 91 [2] 7a 80 [2] 34 8c [2] 38 86 [2] 2f 8d [2] 34 c3 [2] 09 }

  condition:
    any of them
}