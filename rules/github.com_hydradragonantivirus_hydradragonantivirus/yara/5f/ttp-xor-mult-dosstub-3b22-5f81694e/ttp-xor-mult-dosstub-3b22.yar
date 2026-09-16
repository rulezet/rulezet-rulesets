rule TTP_XOR_MULT_DOSStub_3b22 {
  strings:
    $key_3b22 = { 6f 4a [2] 1b 52 [2] 5c 50 [2] 1b 41 [2] 55 4d [2] 59 47 [2] 4e 4c [2] 55 02 [2] 68 }

  condition:
    any of them
}