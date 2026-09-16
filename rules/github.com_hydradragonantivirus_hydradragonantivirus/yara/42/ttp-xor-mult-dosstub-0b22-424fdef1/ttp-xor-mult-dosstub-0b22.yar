rule TTP_XOR_MULT_DOSStub_0b22 {
  strings:
    $key_0b22 = { 5f 4a [2] 2b 52 [2] 6c 50 [2] 2b 41 [2] 65 4d [2] 69 47 [2] 7e 4c [2] 65 02 [2] 58 }

  condition:
    any of them
}