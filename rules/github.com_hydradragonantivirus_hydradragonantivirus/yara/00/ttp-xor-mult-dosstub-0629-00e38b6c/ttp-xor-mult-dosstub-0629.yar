rule TTP_XOR_MULT_DOSStub_0629 {
  strings:
    $key_0629 = { 52 41 [2] 26 59 [2] 61 5b [2] 26 4a [2] 68 46 [2] 64 4c [2] 73 47 [2] 68 09 [2] 55 }

  condition:
    any of them
}