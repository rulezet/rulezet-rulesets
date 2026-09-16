rule TTP_XOR_MULT_DOSStub_5022 {
  strings:
    $key_5022 = { 04 4a [2] 70 52 [2] 37 50 [2] 70 41 [2] 3e 4d [2] 32 47 [2] 25 4c [2] 3e 02 [2] 03 }

  condition:
    any of them
}