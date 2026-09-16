rule TTP_XOR_MULT_DOSStub_1422 {
  strings:
    $key_1422 = { 40 4a [2] 34 52 [2] 73 50 [2] 34 41 [2] 7a 4d [2] 76 47 [2] 61 4c [2] 7a 02 [2] 47 }

  condition:
    any of them
}