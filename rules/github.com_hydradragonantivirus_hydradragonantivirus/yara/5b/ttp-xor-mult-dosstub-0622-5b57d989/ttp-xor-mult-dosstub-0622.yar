rule TTP_XOR_MULT_DOSStub_0622 {
  strings:
    $key_0622 = { 52 4a [2] 26 52 [2] 61 50 [2] 26 41 [2] 68 4d [2] 64 47 [2] 73 4c [2] 68 02 [2] 55 }

  condition:
    any of them
}