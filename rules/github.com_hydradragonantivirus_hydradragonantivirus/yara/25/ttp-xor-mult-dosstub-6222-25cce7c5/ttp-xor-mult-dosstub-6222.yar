rule TTP_XOR_MULT_DOSStub_6222 {
  strings:
    $key_6222 = { 36 4a [2] 42 52 [2] 05 50 [2] 42 41 [2] 0c 4d [2] 00 47 [2] 17 4c [2] 0c 02 [2] 31 }

  condition:
    any of them
}