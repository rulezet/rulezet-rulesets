rule TTP_XOR_MULT_DOSStub_0613 {
  strings:
    $key_0613 = { 52 7b [2] 26 63 [2] 61 61 [2] 26 70 [2] 68 7c [2] 64 76 [2] 73 7d [2] 68 33 [2] 55 }

  condition:
    any of them
}