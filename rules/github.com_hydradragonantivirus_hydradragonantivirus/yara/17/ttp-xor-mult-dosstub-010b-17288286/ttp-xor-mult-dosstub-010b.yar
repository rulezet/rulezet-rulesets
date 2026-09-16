rule TTP_XOR_MULT_DOSStub_010b {
  strings:
    $key_010b = { 55 63 [2] 21 7b [2] 66 79 [2] 21 68 [2] 6f 64 [2] 63 6e [2] 74 65 [2] 6f 2b [2] 52 }

  condition:
    any of them
}