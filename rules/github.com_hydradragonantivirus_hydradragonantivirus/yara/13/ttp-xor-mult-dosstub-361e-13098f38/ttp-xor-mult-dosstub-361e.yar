rule TTP_XOR_MULT_DOSStub_361e {
  strings:
    $key_361e = { 62 76 [2] 16 6e [2] 51 6c [2] 16 7d [2] 58 71 [2] 54 7b [2] 43 70 [2] 58 3e [2] 65 }

  condition:
    any of them
}