rule TTP_XOR_MULT_DOSStub_0617 {
  strings:
    $key_0617 = { 52 7f [2] 26 67 [2] 61 65 [2] 26 74 [2] 68 78 [2] 64 72 [2] 73 79 [2] 68 37 [2] 55 }

  condition:
    any of them
}