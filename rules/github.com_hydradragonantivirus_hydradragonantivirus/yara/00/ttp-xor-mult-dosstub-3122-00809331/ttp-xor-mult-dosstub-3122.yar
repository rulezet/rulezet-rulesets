rule TTP_XOR_MULT_DOSStub_3122 {
  strings:
    $key_3122 = { 65 4a [2] 11 52 [2] 56 50 [2] 11 41 [2] 5f 4d [2] 53 47 [2] 44 4c [2] 5f 02 [2] 62 }

  condition:
    any of them
}