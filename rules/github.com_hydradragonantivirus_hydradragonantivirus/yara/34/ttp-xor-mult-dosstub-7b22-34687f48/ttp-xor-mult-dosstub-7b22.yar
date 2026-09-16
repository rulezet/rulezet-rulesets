rule TTP_XOR_MULT_DOSStub_7b22 {
  strings:
    $key_7b22 = { 2f 4a [2] 5b 52 [2] 1c 50 [2] 5b 41 [2] 15 4d [2] 19 47 [2] 0e 4c [2] 15 02 [2] 28 }

  condition:
    any of them
}