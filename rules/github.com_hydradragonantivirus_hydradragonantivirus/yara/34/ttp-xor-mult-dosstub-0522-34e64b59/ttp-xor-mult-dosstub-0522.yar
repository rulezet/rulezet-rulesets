rule TTP_XOR_MULT_DOSStub_0522 {
  strings:
    $key_0522 = { 51 4a [2] 25 52 [2] 62 50 [2] 25 41 [2] 6b 4d [2] 67 47 [2] 70 4c [2] 6b 02 [2] 56 }

  condition:
    any of them
}