rule TTP_XOR_MULT_DOSStub_5b22 {
  strings:
    $key_5b22 = { 0f 4a [2] 7b 52 [2] 3c 50 [2] 7b 41 [2] 35 4d [2] 39 47 [2] 2e 4c [2] 35 02 [2] 08 }

  condition:
    any of them
}