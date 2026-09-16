rule TTP_XOR_MULT_DOSStub_4722 {
  strings:
    $key_4722 = { 13 4a [2] 67 52 [2] 20 50 [2] 67 41 [2] 29 4d [2] 25 47 [2] 32 4c [2] 29 02 [2] 14 }

  condition:
    any of them
}